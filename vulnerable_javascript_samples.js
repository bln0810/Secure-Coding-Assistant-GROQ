// JavaScript Vulnerabilities Test Cases

// 1. XSS Vulnerability
function displayUserInput(userInput) {
    document.getElementById('output').innerHTML = userInput;
}

// 2. DOM-based XSS
function setWelcomeMessage() {
    var name = location.hash.substring(1);
    document.write("Welcome " + name);
}

// 3. Insecure Direct Object References
function getUserData(userId) {
    fetch('/api/users/' + userId)
        .then(response => response.json())
        .then(data => console.log(data));
}

// 4. Eval Injection
function calculateUserInput(userFormula) {
    return eval(userFormula);
}

// 5. Insecure Authentication
function login(username, password) {
    if(username === "admin" && password === "password123") {
        return "authenticated";
    }
    return "failed";
}

// 6. Unvalidated Redirects
function redirectUser(url) {
    window.location = url;
}

// 7. Insecure Data Storage
function saveUserCredentials(username, password) {
    localStorage.setItem('credentials', JSON.stringify({
        user: username,
        pass: password
    }));
}