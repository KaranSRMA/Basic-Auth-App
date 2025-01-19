// Function to decode JWT token and extract the payload
function decodeJWT(token) {
    const base64Url = token.split('.')[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/'); // Base64 decoding fix
    const jsonPayload = decodeURIComponent(atob(base64).split('').map(function (c) {
        return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
    }).join(''));

    return JSON.parse(jsonPayload);
}

// When the page loads
document.addEventListener('DOMContentLoaded', () => {
    // Retrieve the JWT token from localStorage
    const token = localStorage.getItem('jwt_token');

    if (token) {
        // Decode the JWT token to extract email
        const decodedToken = decodeJWT(token);

        // Check if the email exists in the decoded token
        if (decodedToken.email) {
            document.getElementById('email').value = decodedToken.email;
        }
    }
});

document.getElementById('forgot-password-form').addEventListener('submit', async (e) => {
    e.preventDefault();

    const email = document.getElementById('email').value;

    const response = await fetch('http://localhost:5000/forgot-password', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email }),
    });

    const data = await response.json();

    if (response.status === 200) {
        toastr.success(data.message);
    } else {
        toastr.error(data.message || 'Error sending reset link');
    }
});
