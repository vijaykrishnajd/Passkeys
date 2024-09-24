import Foundation
import AuthenticationServices

class PasskeyManager: NSObject {
    
    static let shared = PasskeyManager()
    
    private override init() {}
    
    // MARK: - Write functioon for savePasskey
    
    func savePasskey(username: String, completion: @escaping (Error?) -> Void) {
        
        let credentialProvider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: "FAKETEAMID.innominds.passKeyDemo")
        
        // Generate a challenge (this should be fetched from your server)
        let challenge = Data("yourChallenge".utf8) // Replace with actual challenge
        
        let registrationRequest = credentialProvider.createCredentialRegistrationRequest(
            challenge: challenge,
            name: username,
            userID: Data(username.utf8)
        )
        
        let authController = ASAuthorizationController(authorizationRequests: [registrationRequest])
        authController.delegate = self
        authController.presentationContextProvider = self
        
        // Save completion handler for later use
        self.registrationCompletion = completion
        
        authController.performRequests()
    }
    
    func signIn(username: String, completion: @escaping (Error?) -> Void) {
        
        let credentialProvider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: "FAKETEAMID.innominds.passKeyDemo")
        
        // Generate a challenge (this should be fetched from your server)
        let challenge = Data("yourChallenge".utf8) // Replace with actual challenge
        
        let assertionRequest = credentialProvider.createCredentialAssertionRequest(challenge: challenge)
        
        let authController = ASAuthorizationController(authorizationRequests: [assertionRequest])
        authController.delegate = self
        authController.presentationContextProvider = self
        
        // Save completion handler for later use
        self.signInCompletion = completion
        
        authController.performRequests()
    }
    
    func validateCredential(credentialID: Data, completion: @escaping (Bool) -> Void) {
        // Send credentialID to your server for validation
        // Assume server returns a boolean indicating success or failure
        // Here we simulate the response
        let isValid = true // Replace with actual server response
        completion(isValid)
    }
    
    // Completion handlers for registration and sign-in
    private var registrationCompletion: ((Error?) -> Void)?
    private var signInCompletion: ((Error?) -> Void)?
}

extension PasskeyManager: ASAuthorizationControllerDelegate, ASAuthorizationControllerPresentationContextProviding {
    
    func authorizationController(controller: ASAuthorizationController, didCompleteWithAuthorization authorization: ASAuthorization) {
        
        if let registration = authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialRegistration {
            let credentialID = registration.credentialID
            // Save credentialID securely (e.g., in Keychain)
            print("Registered passkey with ID: \(credentialID.base64EncodedString())")
            registrationCompletion?(nil) // Notify success
        } else if let assertion = authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialAssertion {
            let credentialID = assertion.credentialID
            // Validate credentialID with your server
            validateCredential(credentialID: credentialID) { isValid in
                if isValid {
                    print("Successfully signed in with passkey ID: \(credentialID.base64EncodedString())")
                    self.signInCompletion?(nil) // Notify success
                } else {
                    self.signInCompletion?(NSError(domain: "PasskeyError", code: 1, userInfo: [NSLocalizedDescriptionKey: "Invalid credentials"]))
                }
            }
        }
    }
    
    func authorizationController(controller: ASAuthorizationController, didCompleteWithError error: Error) {
        print("Authorization failed with error: \(error.localizedDescription)")
        registrationCompletion?(error) // Notify failure for registration
        signInCompletion?(error) // Notify failure for sign-in
    }
    
    func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor {
        return UIApplication.shared.windows.first!.rootViewController!.view.window!
    }
    
}
