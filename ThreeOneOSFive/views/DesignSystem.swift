import SwiftUI
#if canImport(UIKit)
import UIKit
#endif

/// Shared visual language for the PHUCVN IPA DEV "Obsidian Dev Pro" interface.
/// Presentation-only tokens and components live here; file, patch and device services are untouched.
enum AppBrand {
    static let name = "PHUCVN IPA DEV"
    static let artworkAsset = "BrandArtwork"
}

enum DevUIStyle {
    /// 4-tier dark surface elevation hierarchy
    static let canvas = Color(red: 5.0 / 255.0, green: 5.0 / 255.0, blue: 7.0 / 255.0)             // #050507
    static let cardBase = Color(red: 13.0 / 255.0, green: 14.0 / 255.0, blue: 18.0 / 255.0)        // #0D0E12
    static let cardElevated = Color(red: 20.0 / 255.0, green: 22.0 / 255.0, blue: 28.0 / 255.0)    // #14161C
    static let recessedSlot = Color(red: 7.0 / 255.0, green: 8.0 / 255.0, blue: 10.0 / 255.0)      // #07080A
    static let dockTint = Color(red: 11.0 / 255.0, green: 12.0 / 255.0, blue: 16.0 / 255.0)        // #0B0C10
}

enum AppTheme {
    // Preserved Obsidian / Ice-Silver / Emerald-Amber-Crimson semantic palette
    static let accent = Color(red: 0.78, green: 0.82, blue: 0.87)
    static let accentSoft = Color(red: 0.64, green: 0.69, blue: 0.75)
    static let accentDeep = Color(red: 0.46, green: 0.51, blue: 0.58)
    static let pageBackground = DevUIStyle.canvas
    static let consoleBackground = DevUIStyle.cardBase
    static let elevatedBackground = DevUIStyle.cardElevated
    static let recessedBackground = DevUIStyle.recessedSlot
    static let subduedText = Color(red: 0.63, green: 0.67, blue: 0.73)
    static let hairline = Color.white.opacity(0.08)
    static let silverGlow = Color(red: 0.90, green: 0.93, blue: 0.96)
    static let info = Color(red: 0.71, green: 0.77, blue: 0.85)
    static let success = Color(red: 0.36, green: 0.84, blue: 0.62)
    static let warning = Color(red: 0.98, green: 0.70, blue: 0.32)
    static let danger = Color(red: 1.00, green: 0.30, blue: 0.34)

    static let pageInset: CGFloat = 16
    static let rowIconSize: CGFloat = 17
    static let rowIconFrame: CGFloat = 24
    static let fileRowIconSize: CGFloat = 17
    static let fileRowIconFrame: CGFloat = 26
    static let fileRowHeight: CGFloat = 64
    static let appIconSize: CGFloat = 38
    static let emptyIconSize: CGFloat = 30
    static let selectionIconSize: CGFloat = 19
    static let contentCardCornerRadius: CGFloat = 20
    static let contentCardInset: CGFloat = 16
    static let contentCardPadding: CGFloat = 14
}

enum DevHaptics {
    static func light() {
#if canImport(UIKit)
        let generator = UIImpactFeedbackGenerator(style: .light)
        generator.prepare()
        generator.impactOccurred()
#endif
    }
}

/// Top-down Specular Rim Light border (0.75pt) eliminating uniform flat gray strokes.
struct SpecularRimBorder: View {
    var cornerRadius: CGFloat = AppTheme.contentCardCornerRadius
    var color: Color = .white
    var topOpacity: Double = 0.18
    var midOpacity: Double = 0.05
    var bottomOpacity: Double = 0.02
    var lineWidth: CGFloat = 0.75

    var body: some View {
        RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
            .strokeBorder(
                LinearGradient(
                    stops: [
                        .init(color: color.opacity(topOpacity), location: 0.0),
                        .init(color: color.opacity(midOpacity), location: 0.48),
                        .init(color: color.opacity(bottomOpacity), location: 1.0)
                    ],
                    startPoint: .top,
                    endPoint: .bottom
                ),
                lineWidth: lineWidth
            )
            .allowsHitTesting(false)
            .accessibilityHidden(true)
    }
}

struct AppCardBorder: View {
    var cornerRadius: CGFloat = AppTheme.contentCardCornerRadius

    var body: some View {
        SpecularRimBorder(cornerRadius: cornerRadius)
    }
}

/// A restrained specular highlight pass on glass panels.
struct StudioGlassHighlight: View {
    var cornerRadius: CGFloat = AppTheme.contentCardCornerRadius
    var intensity: Double = 1

    var body: some View {
        SpecularRimBorder(
            cornerRadius: cornerRadius,
            topOpacity: 0.14 * intensity,
            midOpacity: 0.03 * intensity,
            bottomOpacity: 0.01 * intensity,
            lineWidth: 0.75
        )
    }
}

/// Fine engineering dot-matrix pattern drawn on Canvas with soft radial edge falloff.
struct DotMatrixBackground: View {
    var spacing: CGFloat = 14
    var dotSize: CGFloat = 1.0
    var opacity: Double = 0.045

    var body: some View {
        Canvas { context, size in
            guard size.width > 0, size.height > 0 else { return }
            let cols = Int(size.width / spacing) + 1
            let rows = Int(size.height / spacing) + 1
            let startX = (size.width - CGFloat(cols - 1) * spacing) * 0.5
            let startY = (size.height - CGFloat(rows - 1) * spacing) * 0.5
            let shading = GraphicsContext.Shading.color(Color.white.opacity(opacity))
            for r in 0..<rows {
                for c in 0..<cols {
                    let x = startX + CGFloat(c) * spacing - dotSize * 0.5
                    let y = startY + CGFloat(r) * spacing - dotSize * 0.5
                    context.fill(
                        Path(ellipseIn: CGRect(x: x, y: y, width: dotSize, height: dotSize)),
                        with: shading
                    )
                }
            }
        }
        .mask {
            RadialGradient(
                colors: [Color.white, Color.white.opacity(0.45), .clear],
                center: .center,
                startRadius: 16,
                endRadius: 210
            )
        }
        .allowsHitTesting(false)
        .accessibilityHidden(true)
    }
}

/// Delicate 6pt corner reticles inside telemetry / hero surfaces.
struct CornerReticles: View {
    var inset: CGFloat = 10
    var armLength: CGFloat = 6
    var opacity: Double = 0.14

    var body: some View {
        GeometryReader { proxy in
            let w = proxy.size.width
            let h = proxy.size.height
            Path { path in
                guard w > inset * 2 + armLength * 2, h > inset * 2 + armLength * 2 else { return }
                let left = inset
                let right = w - inset
                let top = inset
                let bottom = h - inset

                // Top-left
                path.move(to: CGPoint(x: left, y: top + armLength))
                path.addLine(to: CGPoint(x: left, y: top))
                path.addLine(to: CGPoint(x: left + armLength, y: top))

                // Top-right
                path.move(to: CGPoint(x: right - armLength, y: top))
                path.addLine(to: CGPoint(x: right, y: top))
                path.addLine(to: CGPoint(x: right, y: top + armLength))

                // Bottom-left
                path.move(to: CGPoint(x: left, y: bottom - armLength))
                path.addLine(to: CGPoint(x: left, y: bottom))
                path.addLine(to: CGPoint(x: left + armLength, y: bottom))

                // Bottom-right
                path.move(to: CGPoint(x: right - armLength, y: bottom))
                path.addLine(to: CGPoint(x: right, y: bottom))
                path.addLine(to: CGPoint(x: right, y: bottom - armLength))
            }
            .stroke(
                Color.white.opacity(opacity),
                style: StrokeStyle(lineWidth: 1, lineCap: .square, lineJoin: .miter)
            )
        }
        .allowsHitTesting(false)
        .accessibilityHidden(true)
    }
}

/// Live status dot with smooth 2.2s sonar wave ripple.
struct PulseLED: View {
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    var color: Color = AppTheme.success
    var size: CGFloat = 6
    var isAnimated: Bool = true
    @State private var isPulsing = false

    var body: some View {
        Circle()
            .fill(color)
            .frame(width: size, height: size)
            .shadow(color: color.opacity(0.65), radius: 3)
            .overlay {
                if !reduceMotion && isAnimated {
                    Circle()
                        .stroke(color.opacity(isPulsing ? 0 : 0.65), lineWidth: 1.2)
                        .frame(width: size, height: size)
                        .scaleEffect(isPulsing ? 2.4 : 1.0)
                }
            }
            .onAppear {
                guard !reduceMotion && isAnimated, !isPulsing else { return }
                withAnimation(.easeOut(duration: 2.2).repeatForever(autoreverses: false)) {
                    isPulsing = true
                }
            }
            .accessibilityHidden(true)
    }
}

/// Crisp bare SF Symbol with soft radial glow (replaces bulky gray square boxes).
struct AppRowIcon: View {
    let systemName: String
    var tint: Color = AppTheme.accent
    var symbolSize: CGFloat = AppTheme.rowIconSize
    var frameSize: CGFloat = AppTheme.rowIconFrame
    var glowOpacity: Double = 0.25

    var body: some View {
        Image(systemName: systemName)
            .font(.system(size: symbolSize, weight: .semibold))
            .foregroundStyle(tint)
            .shadow(color: tint.opacity(glowOpacity), radius: 6, y: 1)
            .frame(width: frameSize, height: frameSize)
            .accessibilityHidden(true)
    }
}

struct AppLogo: View {
    var size: CGFloat = 44
    var cornerRadius: CGFloat? = nil

    var body: some View {
        let radius = cornerRadius ?? (size * 0.28)
        Image(AppBrand.artworkAsset)
            .resizable()
            .scaledToFill()
            .frame(width: size, height: size)
            .clipShape(RoundedRectangle(cornerRadius: radius, style: .continuous))
            .overlay {
                SpecularRimBorder(
                    cornerRadius: radius,
                    color: .white,
                    topOpacity: 0.45,
                    midOpacity: 0.14,
                    bottomOpacity: 0.05,
                    lineWidth: 0.75
                )
            }
            .overlay {
                RoundedRectangle(cornerRadius: radius, style: .continuous)
                    .fill(
                        LinearGradient(
                            colors: [Color.white.opacity(0.10), .clear, Color.black.opacity(0.14)],
                            startPoint: .topLeading,
                            endPoint: .bottomTrailing
                        )
                    )
            }
            .shadow(color: AppTheme.silverGlow.opacity(0.22), radius: 14, y: 4)
            .shadow(color: .black.opacity(0.45), radius: 8, y: 4)
            .accessibilityHidden(true)
    }
}

struct StudioEyebrow: View {
    let text: String

    var body: some View {
        Text(text.uppercased())
            .font(.system(size: 9.5, weight: .bold, design: .monospaced))
            .tracking(1.6)
            .foregroundStyle(AppTheme.accentSoft)
            .lineLimit(1)
    }
}

struct StudioSectionHeading: View {
    let title: String
    var detail: String? = nil

    var body: some View {
        HStack(alignment: .lastTextBaseline, spacing: 12) {
            Text(title)
                .font(.system(size: 18, weight: .bold, design: .rounded))
                .tracking(-0.25)
                .foregroundStyle(.primary)
            Spacer(minLength: 4)
            if let detail, !detail.isEmpty {
                Text(detail)
                    .font(.system(size: 9.5, weight: .bold, design: .monospaced))
                    .tracking(0.8)
                    .foregroundStyle(AppTheme.subduedText)
            }
        }
    }
}

struct StudioPanel<Content: View>: View {
    var padding: CGFloat = 14
    var cornerRadius: CGFloat = AppTheme.contentCardCornerRadius
    let content: Content

    init(
        padding: CGFloat = 14,
        cornerRadius: CGFloat = AppTheme.contentCardCornerRadius,
        @ViewBuilder content: () -> Content
    ) {
        self.padding = padding
        self.cornerRadius = cornerRadius
        self.content = content()
    }

    var body: some View {
        content
            .padding(padding)
            .background(
                DevUIStyle.cardBase,
                in: RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
            )
            .overlay { SpecularRimBorder(cornerRadius: cornerRadius) }
            .shadow(color: .black.opacity(0.24), radius: 10, y: 4)
    }
}

struct AppPageBackground: View {
    var body: some View {
        ZStack {
            DevUIStyle.canvas
            RadialGradient(
                colors: [
                    AppTheme.accentSoft.opacity(0.045),
                    AppTheme.success.opacity(0.020),
                    .clear
                ],
                center: UnitPoint(x: 0.25, y: 0.04),
                startRadius: 8,
                endRadius: 420
            )
        }
        .ignoresSafeArea()
        .accessibilityHidden(true)
    }
}

struct BrandIdentityPanel: View {
    let version: String

    var body: some View {
        HStack(spacing: 14) {
            AppLogo(size: 56, cornerRadius: 14)
            VStack(alignment: .leading, spacing: 5) {
                Text(AppBrand.name)
                    .font(.system(size: 17, weight: .heavy, design: .rounded))
                    .tracking(-0.35)
                    .foregroundStyle(.primary)
                    .lineLimit(1)
                    .minimumScaleFactor(0.75)
                Text(version)
                    .font(.system(size: 11, weight: .semibold, design: .monospaced))
                    .foregroundStyle(AppTheme.subduedText)
            }
            Spacer(minLength: 0)
            Image(systemName: "sparkle")
                .font(.system(size: 17, weight: .medium))
                .foregroundStyle(AppTheme.accentSoft)
                .accessibilityHidden(true)
        }
        .padding(16)
        .background(
            LinearGradient(
                colors: [DevUIStyle.cardElevated, DevUIStyle.cardBase],
                startPoint: .topLeading,
                endPoint: .bottomTrailing
            ),
            in: RoundedRectangle(cornerRadius: 20, style: .continuous)
        )
        .overlay { SpecularRimBorder(cornerRadius: 20) }
        .shadow(color: .black.opacity(0.32), radius: 18, y: 8)
    }
}

struct AppStatusPill: View {
    let title: String
    var tint: Color = AppTheme.success
    var systemName: String = "checkmark.circle.fill"
    var usePulseLED: Bool = false

    var body: some View {
        HStack(spacing: 6) {
            if usePulseLED {
                PulseLED(color: tint, size: 6)
            } else {
                Image(systemName: systemName)
                    .font(.system(size: 10, weight: .bold))
                    .foregroundStyle(tint)
            }
            Text(title)
                .font(.system(size: 9.5, weight: .bold, design: .rounded))
                .tracking(0.75)
                .foregroundStyle(Color.white.opacity(0.95))
                .lineLimit(1)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 6)
        .background(.ultraThinMaterial, in: Capsule())
        .overlay { Capsule().fill(tint.opacity(0.08)) }
        .overlay { Capsule().strokeBorder(tint.opacity(0.30), lineWidth: 0.75) }
    }
}

struct AppRoundActionButton: View {
    let systemName: String
    let accessibilityTitle: String
    let action: () -> Void

    var body: some View {
        Button {
            DevHaptics.light()
            action()
        } label: {
            Image(systemName: systemName)
                .font(.system(size: 15, weight: .semibold))
                .foregroundStyle(.white.opacity(0.9))
                .frame(width: 40, height: 40)
                .background(.ultraThinMaterial, in: Circle())
                .overlay {
                    Circle().fill(DevUIStyle.cardElevated.opacity(0.65))
                }
                .overlay {
                    Circle()
                        .strokeBorder(
                            LinearGradient(
                                stops: [
                                    .init(color: Color.white.opacity(0.20), location: 0),
                                    .init(color: Color.white.opacity(0.04), location: 1)
                                ],
                                startPoint: .top,
                                endPoint: .bottom
                            ),
                            lineWidth: 0.75
                        )
                }
        }
        .buttonStyle(TactileButtonStyle(cornerRadius: 20, showRimHighlight: false))
        .accessibilityLabel(accessibilityTitle)
    }
}

/// Lightweight sheen pass with zero layout overhead.
struct StudioSheenModifier: ViewModifier {
    let cornerRadius: CGFloat
    let delay: Double

    func body(content: Content) -> some View {
        content
    }
}

/// Instant entrance without opacity drops or layout shifts that hide content.
struct AppEntranceModifier: ViewModifier {
    let isVisible: Bool
    let delay: Double

    func body(content: Content) -> some View {
        content
    }
}

/// Sticky top blur & `#050507 -> .clear` gradient fade so scrolled titles never collide with system status bar.
struct AppTopSafeAreaBlurModifier: ViewModifier {
    func body(content: Content) -> some View {
        content
            .safeAreaInset(edge: .top, spacing: 0) {
                Color.clear
                    .frame(height: 1)
                    .allowsHitTesting(false)
                    .background {
                        VStack(spacing: 0) {
                            Rectangle()
                                .fill(.ultraThinMaterial)
                                .overlay(DevUIStyle.canvas.opacity(0.82))
                            LinearGradient(
                                colors: [DevUIStyle.canvas.opacity(0.88), DevUIStyle.canvas.opacity(0.45), .clear],
                                startPoint: .top,
                                endPoint: .bottom
                            )
                            .frame(height: 16)
                        }
                        .padding(.bottom, -16)
                        .ignoresSafeArea(edges: .top)
                        .allowsHitTesting(false)
                    }
            }
    }
}

extension View {
    func appTopSafeAreaBlur() -> some View {
        modifier(AppTopSafeAreaBlurModifier())
    }

    func appEntrance(isVisible: Bool, delay: Double = 0) -> some View {
        modifier(AppEntranceModifier(isVisible: isVisible, delay: delay))
    }

    func studioSheen(cornerRadius: CGFloat = AppTheme.contentCardCornerRadius, delay: Double = 0) -> some View {
        modifier(StudioSheenModifier(cornerRadius: cornerRadius, delay: delay))
    }
}

/// 120Hz ProMotion tactile spring press feedback with optional top specular rim glint.
struct TactileButtonStyle: ButtonStyle {
    var cornerRadius: CGFloat = AppTheme.contentCardCornerRadius
    var pressedScale: CGFloat = 0.975
    var showRimHighlight: Bool = true

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .overlay {
                if showRimHighlight && configuration.isPressed {
                    SpecularRimBorder(
                        cornerRadius: cornerRadius,
                        color: .white,
                        topOpacity: 0.34,
                        midOpacity: 0.08,
                        bottomOpacity: 0.02,
                        lineWidth: 1.0
                    )
                }
            }
            .scaleEffect(configuration.isPressed ? pressedScale : 1.0)
            .opacity(configuration.isPressed ? 0.93 : 1.0)
            .animation(.spring(response: 0.28, dampingFraction: 0.72), value: configuration.isPressed)
    }
}

/// Preserved convenience button style delegating to TactileButtonStyle across existing views.
struct AppPressableStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        TactileButtonStyle(cornerRadius: AppTheme.contentCardCornerRadius).makeBody(configuration: configuration)
    }
}
