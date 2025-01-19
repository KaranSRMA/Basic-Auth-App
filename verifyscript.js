const urlParams = new URLSearchParams(window.location.search);
const email = urlParams.get('email');
const token = urlParams.get('token');

const button = document.getElementById('verified');

button.addEventListener('click', async function () {
    // Send a POST request to the server
    const response = await fetch('http://localhost:5000/verification', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email, token }) // Optionally send data
    })

    const data = await response.json()
    if (response.status === 200) {
        toastr.success(data.message) // Log the response from the server
    } else {
        toastr.error(data.message);
    }
});