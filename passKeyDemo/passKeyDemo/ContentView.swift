//
//  ContentView.swift
//  passKeyDemo
//
//  Created by Vijaykrishna Jonnalagadda on 18/09/24.
//

import SwiftUI
import Security
import AuthenticationServices

struct ContentView: View {
    
    @State private var username: String = ""
    @State private var password: String = ""
    @State private var isLoginSuccessful: Bool = false
    @State private var showAlert: Bool = false
    @State var request: ASAuthorizationPasswordRequest?
    
    
    
    var body: some View {
        VStack {
            Text("Login")
                .font(.largeTitle)
                .padding()
            
            TextField("Username", text: $username)
                .textFieldStyle(RoundedBorderTextFieldStyle())
                .padding()
            
            SecureField("Password", text: $password)
                .textFieldStyle(RoundedBorderTextFieldStyle())
                .padding()
            
            Button(action: {
                handleLogin()
            }) {
                Text("Login")
                    .foregroundColor(.white)
                    .padding()
                    .frame(maxWidth: .infinity)
                    .background(Color.blue)
                    .cornerRadius(8)
            }
            .padding()
            Spacer()
        }
        .padding()
        .alert(isPresented: $showAlert) {
            Alert(title: Text("Login Failed"), message: Text("Invalid username or password"), dismissButton: .default(Text("OK")))
        }
    }
    
    private func handleLogin() {
        if username.count>0 {
            
        }
        if username == "User" && password == "password" {
            isLoginSuccessful = true
            print("UserName is :\(username) and Password is :\(password)")
            
        } else {
            showAlert = true
        }
    }
    
    // Modal passkey request
    
    
    
    
}




#Preview {
    ContentView()
}
