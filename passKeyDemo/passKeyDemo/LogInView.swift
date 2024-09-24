import SwiftUI

struct LoginView: View {
    
    @State private var username: String = ""
    @State private var password: String = ""
    @State private var showAlert = false
    @State private var alertMessage = ""

    var body: some View {
        VStack {
            TextField("Username", text: $username)
                          .textFieldStyle(RoundedBorderTextFieldStyle())
                          .padding()
                          .onAppear {
                              // Autofill password when the view appears
                              if let fetchedPassword = Authentication.sharedInstance.fetchCredentials(for: username) {
                                  password = fetchedPassword
                              }
                          }
                          .onChange(of: username) { newValue in
                              // Fetch the password whenever the username changes
                              if let fetchedPassword = Authentication.sharedInstance.fetchCredentials(for: newValue) {
                                  password = fetchedPassword
                              } else {
                                  password = "" // Clear password if no matching username is found
                              }
                          }
            
            SecureField("Password", text: $password)
                .textFieldStyle(RoundedBorderTextFieldStyle())
                .padding()
            
            Button("Sign Up") {
                Authentication.sharedInstance.saveCredentials(username: username, password: password)
            }
            .padding()

            Button("Sign in with Passkey") {
                authenticateUser()
            }
            .padding()
        }
        .alert(isPresented: $showAlert) {
            Alert(title: Text("Message"), message: Text(alertMessage), dismissButton: .default(Text("OK")))
        }
    }

    private func authenticateUser() {
        
        
        Authentication.sharedInstance.signIn { success, message in
            if success {
                alertMessage = "Logged in successfully as \(message ?? "unknown user")"
            } else {
                alertMessage = "Login failed: \(message ?? "unknown error")"
            }
            showAlert = true
        }
    }
}

struct LoginView_Previews: PreviewProvider {
    static var previews: some View {
        LoginView()
    }
}
