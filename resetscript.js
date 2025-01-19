const urlParams = new URLSearchParams(window.location.search);
const email = urlParams.get('email');
const token = urlParams.get('token');

// Handle form submission
document.getElementById('resetPasswordForm').addEventListener('submit', async function (e) {
    e.preventDefault();

    const newPassword = document.getElementById('newPassword').value;

    // Send the email, token, and new password to the server
    const response = await fetch('/reset-password', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ email, token, newPassword })
    });

    const result = await response.json();
    document.getElementById('resetPasswordForm').reset()
    toastr.success(result.message); // Show message from the server
});