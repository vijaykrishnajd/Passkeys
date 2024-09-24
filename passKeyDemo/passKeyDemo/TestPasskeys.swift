//
//  TestPasskeys.swift
//  passKeyDemo
//
//  Created by Vijaykrishna Jonnalagadda on 18/09/24.
//


import SwiftUI
import AuthenticationServices

struct LoginViewNew : View {
    
    @State private var username: String = ""
    @State private var password: String = ""
    @State private var showAlert = false
    @State private var alertMessage = ""

    var body: some View {
        VStack {
            
            Text("Login with Passkeys")
                .font(.largeTitle)
                .padding()

            TextField("Username", text: $username)
                .textFieldStyle(RoundedBorderTextFieldStyle())
                .padding()
                
            SecureField("Password", text: $password)
                .textFieldStyle(RoundedBorderTextFieldStyle())
                .padding()
            
            Button("SignUp"){
                savePasskey()
            }

            Button("Sign in with Passkey") {
                authenticateUser()
            }
            .padding()
            .alert(isPresented: $showAlert) {
                Alert(title: Text("Message"), message: Text(alertMessage), dismissButton: .default(Text("OK")))
            }
        }
        .padding()
    }
    
    private func savePasskey() {
        PasskeyManager.shared.savePasskey(username: username) { error in
            if let error = error {
                print("Error saving passkey: \(error)")
            } else {
                print("Passkey saved successfully")
            }
        }

    }

    private func authenticateUser() {
        PasskeyManager.shared.signIn(username: username) { error in
            if let error = error {
                print("Error signing in: \(error)")
            } else {
                print("Signed in successfully")
            }
        }

    }
    
    
}

struct LoginNewView_Previews: PreviewProvider {
    static var previews: some View {
        LoginView()
    }
}


