import Foundation
import AuthenticationServices
import Security

class Authentication: NSObject, ASAuthorizationControllerDelegate, ASAuthorizationControllerPresentationContextProviding {
    
    static let sharedInstance = Authentication()
    
    private override init() {}
    
    func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor {
        // Return the current window's presentation anchor
        return UIApplication.shared.windows.first!.rootViewController!.view.window!
    }
    
    // SignIn with a completion handler
    func signIn(completion: @escaping (Bool, String?) -> Void) {
        let challenge: Data = Data() // Replace with actual challenge fetched from your server
        
        let passkeyProvider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: "applinks:innominds.com")
        let passkeyRequest = passkeyProvider.createCredentialAssertionRequest(challenge: challenge)
        let passwordRequest = ASAuthorizationPasswordProvider().createRequest()
        let signInWithAppleRequest = ASAuthorizationAppleIDProvider().createRequest()
        let controller = ASAuthorizationController(authorizationRequests: [passkeyRequest, passwordRequest, signInWithAppleRequest])
        controller.delegate = self
        controller.presentationContextProvider = self
        controller.performRequests()
        self.completion = completion
    }
    
    private var completion: ((Bool, String?) -> Void)?
    
    func authorizationController(controller: ASAuthorizationController, didCompleteWithAuthorization authorization: ASAuthorization) {
        if let passkeyCredential = authorization.credential as? ASPasswordCredential {
            let username = passkeyCredential.user
            let password = passkeyCredential.password
            // Save credentials securely
            saveCredentials(username: username, password: password)
            print("Successfully logged in with username: \(username)")
            completion?(true, username) // Notify success
        } else {
            completion?(false, "Unexpected credential type.")
        }
    }

    func authorizationController(controller: ASAuthorizationController, didCompleteWithError error: Error) {
        print("Authorization failed: \(error.localizedDescription)")
        completion?(false, error.localizedDescription) // Notify failure
    }
    
    // Save credentials in Keychain
     func saveCredentials(username: String, password: String) {
        let account = username
        let passwordData = password.data(using: .utf8)!
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account,
            kSecValueData as String: passwordData
        ]

        // Delete any existing credentials
        SecItemDelete(query as CFDictionary)

        // Add new credentials to the Keychain
        let status = SecItemAdd(query as CFDictionary, nil)
        if status == errSecSuccess {
            print("Credentials saved successfully.")
        } else {
            print("Error saving credentials: \(status)")
        }
    }
    
    // Fetch credentials from Keychain
    func fetchCredentials(for username: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: username,
            kSecReturnData as String: kCFBooleanTrue!,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)

        if status == errSecSuccess, let passwordData = item as? Data {
            return String(data: passwordData, encoding: .utf8)
        } else {
            print("Error fetching credentials: \(status)")
            return nil
        }
    }
    
    // Autofill example (optional)
    func autofillPassword(for username: String) -> (username: String?, password: String?) {
        if let password = fetchCredentials(for: username) {
            return (username: username, password: password)
        }
        return (username: nil, password: nil)
    }
}
