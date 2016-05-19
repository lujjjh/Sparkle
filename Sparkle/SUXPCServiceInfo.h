//
//  SUXPCServiceInfo.h
//  Sparkle
//
//  Created by Mayur Pawashe on 4/17/16.
//  Copyright © 2016 Sparkle Project. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

BOOL SUXPCServiceExists(NSString *bundleName);

NSBundle * _Nullable SUXPCServiceBundle(NSString *bundleName);

NS_ASSUME_NONNULL_END
