/*
 Copyright © Roman Zechmeister, 2010
 
 Dieses Programm ist freie Software. Sie können es unter den Bedingungen 
 der GNU General Public License, wie von der Free Software Foundation 
 veröffentlicht, weitergeben und/oder modifizieren, entweder gemäß 
 Version 3 der Lizenz oder (nach Ihrer Option) jeder späteren Version.
 
 Die Veröffentlichung dieses Programms erfolgt in der Hoffnung, daß es Ihnen 
 von Nutzen sein wird, aber ohne irgendeine Garantie, sogar ohne die implizite 
 Garantie der Marktreife oder der Verwendbarkeit für einen bestimmten Zweck. 
 Details finden Sie in der GNU General Public License.
 
 Sie sollten ein Exemplar der GNU General Public License zusammen mit diesem 
 Programm erhalten haben. Falls nicht, siehe <http://www.gnu.org/licenses/>.
*/

#import <Security/Security.h>
#import "GPGDefaults.h"
#import "KeychainSupport.h"
#import <LocalAuthentication/LocalAuthentication.h>;


#define GPG_SERVICE_NAME "GnuPG"

void storePassphraseInKeychain(NSString *fingerprint, NSString *passphrase, NSString *label) {
	int status;
	SecKeychainItemRef itemRef = nil;
	SecKeychainRef keychainRef = nil;
	
    NSString *keychainPath = [[GPGDefaults gpgDefaults] valueForKey:@"KeychainPath"];
    const char* path = [keychainPath UTF8String];
    
    if(keychainPath && [keychainPath length]) {
        if(SecKeychainOpen(path, &keychainRef) != 0) {
            return;
        }
    }
    else if(SecKeychainCopyDefault(&keychainRef) != 0) {
        return;
    }
	
	if (NSAppKitVersionNumber > NSAppKitVersionNumber10_12_1) {
        CFErrorRef cfError = NULL;
        SecAccessControlRef accessCtrl;
        accessCtrl = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                                     kSecAttrAccessibleWhenUnlocked,
                                                     kSecAccessControlUserPresence, &cfError);
        if (!accessCtrl || cfError != NULL) {
            NSLog(@"Couldn't create accessCtrl");
            return;
        }

        if (passphrase) {
            LAContext *context = [[LAContext alloc] init];
            dispatch_semaphore_t sema = dispatch_semaphore_create(0);

            [context evaluateAccessControl:accessCtrl operation:LAPolicyDeviceOwnerAuthentication localizedReason:@"Add Secret to Keychain" reply:^(BOOL success, NSError * error) {
                if (success) {
                    NSDictionary *attributes = @{
                                                 (id)kSecClass: (id)kSecClassGenericPassword,
                                                 (id)kSecAttrService: @GPG_SERVICE_NAME,
                                                 (id)kSecAttrAccount: fingerprint,
                                                 (id)kSecValueData: [passphrase dataUsingEncoding:NSUTF8StringEncoding],
                                                 (id)kSecUseAuthenticationUI: (id)kSecUseAuthenticationUIAllow,
                                                 (id)kSecAttrAccessControl: (__bridge_transfer id)accessCtrl,
                                                 (id)kSecUseAuthenticationContext: context,
                                                 };

                    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)attributes, nil);
                    if (status != errSecSuccess) {
                        NSLog(@"Unknown error: %d\n", status);
                    }
                }
                dispatch_semaphore_signal(sema);
            }];

            dispatch_semaphore_wait(sema, DISPATCH_TIME_FOREVER);
            dispatch_release(sema);
        }
    } else if (NSAppKitVersionNumber >= NSAppKitVersionNumber10_7) {
		
		NSDictionary *attributes = [NSDictionary dictionaryWithObjectsAndKeys:
									kSecClassGenericPassword, kSecClass,
									@GPG_SERVICE_NAME, kSecAttrService,
									fingerprint, kSecAttrAccount,
									kCFBooleanTrue, kSecReturnRef,
									keychainRef, kSecUseKeychain,
									nil];

		int status = SecItemCopyMatching((__bridge CFDictionaryRef)attributes, (CFTypeRef *)&itemRef);
		if (status == 0) {
			SecKeychainItemDelete(itemRef);
			CFRelease(itemRef);
		}


		if (passphrase) {
			attributes = [NSDictionary dictionaryWithObjectsAndKeys:
						  kSecClassGenericPassword, kSecClass,
						  @GPG_SERVICE_NAME, kSecAttrService,
						  fingerprint, kSecAttrAccount,
						  [passphrase dataUsingEncoding:NSUTF8StringEncoding], kSecValueData,
						  label ? label : @GPG_SERVICE_NAME, kSecAttrLabel,
						  keychainRef, kSecUseKeychain,
						  nil];

			SecItemAdd((__bridge CFDictionaryRef)attributes, nil);
		}

	} else { /* Mac OS X 10.6 */
		status = SecKeychainFindGenericPassword (keychainRef, strlen(GPG_SERVICE_NAME), GPG_SERVICE_NAME,
												 [fingerprint lengthOfBytesUsingEncoding:NSUTF8StringEncoding], fingerprint.UTF8String, NULL, NULL, &itemRef);
		if (status == 0) {
			SecKeychainItemDelete(itemRef);
			CFRelease(itemRef);
		}

		if (passphrase) {
			SecKeychainAddGenericPassword (keychainRef, strlen(GPG_SERVICE_NAME), GPG_SERVICE_NAME,
										   [fingerprint lengthOfBytesUsingEncoding:NSUTF8StringEncoding], fingerprint.UTF8String, [passphrase lengthOfBytesUsingEncoding:NSUTF8StringEncoding], passphrase.UTF8String, NULL);
		}
	}
	
	
	CFRelease(keychainRef);
}

NSString *getPassphraseFromKeychain(NSString *fingerprint) {
	int status;
	SecKeychainRef keychainRef = nil;
	
    NSString *keychainPath = [[GPGDefaults gpgDefaults] valueForKey:@"KeychainPath"];
    const char* path = [keychainPath UTF8String];
    
    if(keychainPath && [keychainPath length]) {
        if(SecKeychainOpen(path, &keychainRef) != 0)
            return nil;
    }

	__block NSString *passphrase = nil;
	
    if (NSAppKitVersionNumber > NSAppKitVersionNumber10_12_1) {
        CFErrorRef cfError = NULL;
        SecAccessControlRef accessCtrl;
        accessCtrl = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                                     kSecAttrAccessibleWhenUnlocked,
                                                     kSecAccessControlUserPresence, &cfError);
        if (!accessCtrl || cfError != NULL) {
            printf("Couldn't create accessCtrl\n");
            return passphrase;
        }

        LAContext *context = [[LAContext alloc] init];
        dispatch_semaphore_t sema = dispatch_semaphore_create(0);

        [context evaluateAccessControl:accessCtrl operation:LAPolicyDeviceOwnerAuthentication localizedReason:@"Add Secret to Keychain" reply:^(BOOL success, NSError * error) {
            if (success) {
                NSDictionary *attributes = [NSDictionary dictionaryWithObjectsAndKeys:
                                            kSecClassGenericPassword, kSecClass,
                                            @GPG_SERVICE_NAME, kSecAttrService,
                                            fingerprint, kSecAttrAccount,
                                            kCFBooleanTrue, kSecReturnData,
                                            keychainRef, kSecUseKeychain,
                                            nil];
                CFTypeRef passphraseData = nil;

                int copy_status = SecItemCopyMatching((__bridge CFDictionaryRef)attributes, &passphraseData);

                if (keychainRef) {
                    CFRelease(keychainRef);
                }

                if (copy_status != 0) {
                    dispatch_semaphore_signal(sema);
                    return;
                }

                passphrase = [[NSString alloc] initWithData:(__bridge NSData *)passphraseData encoding:NSUTF8StringEncoding];

                CFRelease(passphraseData);
                dispatch_semaphore_signal(sema);
            }
        }];
        dispatch_semaphore_wait(sema, DISPATCH_TIME_FOREVER);
        dispatch_release(sema);
    } else if (NSAppKitVersionNumber >= NSAppKitVersionNumber10_7) {
		NSDictionary *attributes = [NSDictionary dictionaryWithObjectsAndKeys:
									kSecClassGenericPassword, kSecClass,
									@GPG_SERVICE_NAME, kSecAttrService,
									fingerprint, kSecAttrAccount,
									kCFBooleanTrue, kSecReturnData,
									keychainRef, kSecUseKeychain,
									nil];
		CFTypeRef passphraseData = nil;
		
		status = SecItemCopyMatching((__bridge CFDictionaryRef)attributes, &passphraseData);
		
		
		if (keychainRef) CFRelease(keychainRef);
		if (status != 0) {
			return nil;
		}
		
		passphrase = [[NSString alloc] initWithData:(__bridge NSData *)passphraseData encoding:NSUTF8StringEncoding];
		
		CFRelease(passphraseData);
	} else { /* Mac OS X 10.6 */
		UInt32 passphraseLength;
		void *passphraseData = NULL;
		
		status = SecKeychainFindGenericPassword (keychainRef, strlen(GPG_SERVICE_NAME), GPG_SERVICE_NAME,
												 [fingerprint lengthOfBytesUsingEncoding:NSUTF8StringEncoding], fingerprint.UTF8String, &passphraseLength, &passphraseData, NULL);
		
		
		if (keychainRef) CFRelease(keychainRef);
		if (status != 0) {
			return nil;
		}
		
		passphrase = [[NSString alloc] initWithBytes:passphraseData length:passphraseLength encoding:NSUTF8StringEncoding];
		
		
		SecKeychainItemFreeContent(NULL, passphraseData);
	}
	
	
	return passphrase;
}

