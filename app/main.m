//
//  main.m
//  iSH
//
//  Created by Theodore Dubois on 10/17/17.
//

#import <UIKit/UIKit.h>
#import "AppDelegate.h"
extern void run_at_boot(void);
#import <Foundation/Foundation.h>
#import <Foundation/NSProcessInfo.h>

void disable_app_nap(void)
{
   if ([[NSProcessInfo processInfo] respondsToSelector:@selector(beginActivityWithOptions:reason:)])
   {
      [[NSProcessInfo processInfo] beginActivityWithOptions:0x00FFFFFF reason:@"Not sleepy and don't want to nap"];
   }
}
#import "ExceptionExfiltrator.h"

int main(int argc, char * argv[]) {
/*    NSString *appContainerPath = NSHomeDirectory();
    NSString *documentsPath = [appContainerPath stringByAppendingPathComponent:@"iCloud"];
    NSString *filePath = [documentsPath stringByAppendingPathComponent:@"iSH-AOK_outputfile.txt"];
    FILE *newStdout = freopen([filePath UTF8String], "a+", stdout);
    if (newStdout == NULL) {
        NSLog(@"Failed to open file for stdout: %@", filePath);
        // Handle error
    }
    NSString *filePathE = [documentsPath stringByAppendingPathComponent:@"iSH-AOK_errorfile.txt"];
    FILE *newStderr = freopen([filePathE UTF8String], "a+", stderr);
    if (newStderr == NULL) {
        NSLog(@"Failed to open file for stderr: %@", filePathE);
        // Handle error
    } */
    run_at_boot();
    NSSetUncaughtExceptionHandler(iSHExceptionHandler);
    @autoreleasepool {
        disable_app_nap();  // No napping I say. -mke
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class]));
    }
}
