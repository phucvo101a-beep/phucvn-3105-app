import AVFoundation
import Combine
import Foundation

/// Maintains an ultra-low-overhead silent audio playback session (`UIBackgroundModes: audio`)
/// while `LocalDev` (RSD `10.7.0.1:49152`) is live or active file/backup transfers run,
/// preventing iOS from suspending background TCP/utun sockets on app switches.
public final class BackgroundKeepAliveManager: ObservableObject {
    public static let shared = BackgroundKeepAliveManager()

    private static let enabledDefaultsKey = "3105.localdev.background_keepalive"

    @Published public private(set) var isActive: Bool = false
    @Published public var isUserEnabled: Bool

    private let lock = NSLock()
    private var isConnectionLive: Bool = false
    private var activeWorkTokens = Set<UUID>()

    private var audioEngine: AVAudioEngine?
    private var playerNode: AVAudioPlayerNode?
    private var silentBuffer: AVAudioPCMBuffer?
    private var interruptionObserver: NSObjectProtocol?
    private var configChangeObserver: NSObjectProtocol?

    private init() {
        let saved = UserDefaults.standard.object(forKey: Self.enabledDefaultsKey) as? Bool ?? true
        self.isUserEnabled = saved
        registerNotifications()
    }

    deinit {
        if let obs = interruptionObserver {
            NotificationCenter.default.removeObserver(obs)
        }
        if let obs = configChangeObserver {
            NotificationCenter.default.removeObserver(obs)
        }
    }

    public func setUserEnabled(_ enabled: Bool) {
        lock.lock()
        let changed = (isUserEnabled != enabled)
        UserDefaults.standard.set(enabled, forKey: Self.enabledDefaultsKey)
        lock.unlock()

        if Thread.isMainThread {
            self.isUserEnabled = enabled
        } else {
            DispatchQueue.main.async {
                self.isUserEnabled = enabled
            }
        }
        if changed {
            reconcilePlaybackLocked(explicitUserEnabled: enabled)
        }
    }

    public func setConnectionLive(_ live: Bool) {
        lock.lock()
        let changed = (isConnectionLive != live)
        isConnectionLive = live
        lock.unlock()
        if changed || (!live && isActive) {
            reconcilePlaybackLocked(explicitUserEnabled: nil)
        }
    }

    public func beginWorkToken() -> UUID {
        let token = UUID()
        lock.lock()
        activeWorkTokens.insert(token)
        lock.unlock()
        reconcilePlaybackLocked(explicitUserEnabled: nil)
        return token
    }

    public func endWorkToken(_ token: UUID) {
        lock.lock()
        activeWorkTokens.remove(token)
        lock.unlock()
        reconcilePlaybackLocked(explicitUserEnabled: nil)
    }

    public func stopAllImmediately() {
        lock.lock()
        isConnectionLive = false
        activeWorkTokens.removeAll()
        stopAudioLocked()
        lock.unlock()
        publishActiveState(false)
    }

    private func registerNotifications() {
        interruptionObserver = NotificationCenter.default.addObserver(
            forName: AVAudioSession.interruptionNotification,
            object: AVAudioSession.sharedInstance(),
            queue: nil
        ) { [weak self] notification in
            self?.handleInterruption(notification)
        }

        configChangeObserver = NotificationCenter.default.addObserver(
            forName: .AVAudioEngineConfigurationChange,
            object: nil,
            queue: nil
        ) { [weak self] _ in
            self?.reconcilePlaybackLocked(explicitUserEnabled: nil)
        }
    }

    private func handleInterruption(_ notification: Notification) {
        guard let info = notification.userInfo,
              let rawType = info[AVAudioSessionInterruptionTypeKey] as? UInt,
              let type = AVAudioSession.InterruptionType(rawValue: rawType) else {
            return
        }

        switch type {
        case .began:
            lock.lock()
            stopAudioLocked()
            lock.unlock()
            publishActiveState(false)
        case .ended:
            reconcilePlaybackLocked(explicitUserEnabled: nil)
        @unknown default:
            break
        }
    }

    private func reconcilePlaybackLocked(explicitUserEnabled: Bool?) {
        lock.lock()
        let userAllowed = explicitUserEnabled ?? (UserDefaults.standard.object(forKey: Self.enabledDefaultsKey) as? Bool ?? true)
        let shouldRun = userAllowed && (isConnectionLive || !activeWorkTokens.isEmpty)
        if shouldRun {
            let started = ensureAudioRunningLocked()
            lock.unlock()
            publishActiveState(started)
        } else {
            stopAudioLocked()
            lock.unlock()
            publishActiveState(false)
        }
    }

    private func ensureAudioRunningLocked() -> Bool {
        if let engine = audioEngine, engine.isRunning,
           let player = playerNode, player.isPlaying {
            return true
        }

        let session = AVAudioSession.sharedInstance()
        do {
            try session.setCategory(.playback, mode: .default, options: [.mixWithOthers])
            try session.setActive(true)
        } catch {
            log("keepalive: AVAudioSession activation failed — \(error.localizedDescription)")
            return false
        }

        let engine = audioEngine ?? AVAudioEngine()
        let player = playerNode ?? AVAudioPlayerNode()

        // Ultra-lightweight 8 kHz mono PCM buffer (1 second of zero-amplitude samples)
        guard let format = AVAudioFormat(standardFormatWithSampleRate: 8000, channels: 1),
              let buffer = silentBuffer ?? AVAudioPCMBuffer(pcmFormat: format, frameCapacity: 8000) else {
            return false
        }
        buffer.frameLength = 8000
        if let channelData = buffer.floatChannelData?[0] {
            channelData.initialize(repeating: 0, count: 8000)
        }

        if engine.attachedNodes.contains(player) == false {
            engine.attach(player)
        }
        engine.connect(player, to: engine.mainMixerNode, format: format)
        engine.mainMixerNode.outputVolume = 0.0

        do {
            try engine.start()
            player.stop()
            player.scheduleBuffer(buffer, at: nil, options: .loops, completionHandler: nil)
            player.play()
            audioEngine = engine
            playerNode = player
            silentBuffer = buffer
            return true
        } catch {
            log("keepalive: AVAudioEngine start failed — \(error.localizedDescription)")
            stopAudioLocked()
            return false
        }
    }

    private func stopAudioLocked() {
        playerNode?.stop()
        if let engine = audioEngine, engine.isRunning {
            engine.stop()
        }
        audioEngine?.reset()
        audioEngine = nil
        playerNode = nil
        try? AVAudioSession.sharedInstance().setActive(false, options: .notifyOthersOnDeactivation)
    }

    private func publishActiveState(_ active: Bool) {
        if Thread.isMainThread {
            if self.isActive != active {
                self.isActive = active
            }
        } else {
            DispatchQueue.main.async {
                if self.isActive != active {
                    self.isActive = active
                }
            }
        }
    }
}
