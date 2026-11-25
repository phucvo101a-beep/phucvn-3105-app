#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

NS_ASSUME_NONNULL_BEGIN

/// Returns a dictionary mapping bundleID -> @{ @"name": NSString, @"icon": UIImage }.
/// Uses the private LSApplicationWorkspace API (stable across iOS 14+).
NSDictionary<NSString *, NSDictionary *> *installedAppInfo(void);

/// Fetches an icon for a single bundle ID via LSApplicationProxy.
UIImage *iconForBundleID(NSString *bundleID);

/// Returns @{ @"name": NSString, @"icon": UIImage } for a single bundle ID.
NSDictionary *appInfoForBundleID(NSString *bundleID);

/// Opens an installed app using LaunchServices. Returns NO when the private
/// selector is unavailable or the requested bundle cannot be opened.
BOOL openApplicationForBundleID(NSString *bundleID);

/// Constant-barrier memory wipe immune to dead-store elimination & rsize_t SDK differences.
static inline void p3105_secure_zero(void * _Nullable ptr, size_t len) {
    if (!ptr || len == 0) {
        return;
    }
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (len--) {
        *p++ = 0;
    }
}

NS_ASSUME_NONNULL_END
