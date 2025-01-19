document.getElementById('login-form').addEventListener('submit', async (e) => {
    e.preventDefault(); // Prevent default form submission

    const username = document.getElementById('login-user').value;
    const password = document.getElementById('login-password').value;
    
    const response = await fetch('http://localhost:5000/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ username, password }),
    });

    const data = await response.json();

    if (data.token) {
        toastr.success('Login successful');

        // Store the JWT token and user details in localStorage
        localStorage.setItem("jwt_token", data.token);

        // Redirect to a new page or show the user details page
        window.location.href = '/user.html';  // Redirect to user details page
    } else {
        toastr.error(data.message || 'Login failed. Please try again.');
    }
});


async function isverified(e) {
    const email = e.target.value;
    const message = document.getElementById('dispnone');

    const response = await fetch('http://localhost:5000/isverifieduser', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email })
    });

    const data = await response.json(); // Get the response data

    if (response.status === 200 && data.verified === false) {
        // If the email is not verified, show the message
        toastr.error("Email is not verified")
        message.style.display = 'block';
    } else {
        // Hide the verification message if verified
        message.style.display = 'none';
    }
}



async function resendemail(e) {
    const email = document.getElementById('signup-email').value;
    const respone = await fetch('http://localhost:5000/resendMail', {
        method: "POST",
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email })
    });

    const data = await respone.json()

    if (respone.status === 200) {
        toastr.success(data.message)
    } else {
        toastr.error(data.message)
    }
}

// Handle Signup
document.getElementById('signup-form').addEventListener('submit', async (e) => {
    e.preventDefault(); // Prevent default form submission

    const username = document.getElementById('signup-username').value;
    const email = document.getElementById('signup-email').value;
    const phone = document.getElementById('signup-phone').value;
    const password = document.getElementById('signup-password').value;
    const confirmpassword = document.getElementById('signup-confirm-password').value;

    // Email validation regex (simple check for proper email format)
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        toastr.error('Please enter a valid email address.');
        return;  // Stop form submission
    }

    // Phone validation regex (simple check for 10-digit phone numbers)
    const phoneRegex = /^[0-9]{10}$/;
    if (!phoneRegex.test(phone)) {
        toastr.error('Please enter a valid 10-digit phone number.');
        return;  // Stop form submission
    }

    // Proceed with the registration API call if both validations pass
    const response = await fetch('http://localhost:5000/register', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ username, email, phone, password, confirmpassword }),
    });

    const data = await response.json();

    if (response.status === 200) {
        toastr.success(data.message);

        // Reset the signup form after successful registration
        document.getElementById('signup-form').reset(); // Reset form fields
    } else {
        toastr.error(data.message || "Error registering user "); // Display error message from the server
    }
});
