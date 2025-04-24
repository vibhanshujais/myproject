// static/js/script.js
document.addEventListener('DOMContentLoaded', () => {
    // Form validation
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        form.addEventListener('submit', (e) => {
            const inputs = form.querySelectorAll('input[required]');
            let valid = true;
            
            inputs.forEach(input => {
                if (!input.value.trim()) {
                    valid = false;
                    input.style.borderColor = '#dc3545';
                    input.setAttribute('aria-invalid', 'true');
                } else {
                    input.style.borderColor = '#2a5298';
                    input.setAttribute('aria-invalid', 'false');
                }
            });
            
            if (!valid) {
                e.preventDefault();
                alert('Please fill in all required fields');
            }
        });
    });

    // Interactive document cards
    const docCards = document.querySelectorAll('.doc-card');
    docCards.forEach(card => {
        card.addEventListener('click', () => {
            card.style.background = '#e9ecef';
            setTimeout(() => {
                card.style.background = '#f8f9fa';
            }, 200);
        });
    });
});



document.addEventListener('DOMContentLoaded', () => {
    // Form validation
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        form.addEventListener('submit', (e) => {
            const inputs = form.querySelectorAll('input[required]');
            let valid = true;
            
            inputs.forEach(input => {
                if (!input.value.trim()) {
                    valid = false;
                    input.style.borderColor = '#dc3545';
                    input.setAttribute('aria-invalid', 'true');
                } else {
                    input.style.borderColor = '#2a5298';
                    input.setAttribute('aria-invalid', 'false');
                }
            });
            
            if (!valid) {
                e.preventDefault();
                alert('Please fill in all required fields');
            }
        });
    });

    // Interactive document cards
    const docCards = document.querySelectorAll('.doc-card');
    docCards.forEach(card => {
        card.addEventListener('click', () => {
            card.style.background = '#e9ecef';
            setTimeout(() => {
                card.style.background = '#f8f9fa';
            }, 200);
        });
    });
});

// Password strength checker
function checkPasswordStrength(input) {
    const password = input.value;
    const strengthDiv = document.getElementById('password-strength');
    const minLength = 8;
    const hasUpperCase = /[A-Z]/.test(password);
    const hasLowerCase = /[a-z]/.test(password);
    const hasNumber = /\d/.test(password);
    const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);

    if (password.length === 0) {
        strengthDiv.textContent = '';
        strengthDiv.style.color = '#dc3545';
        return;
    }

    if (password.length < minLength || !hasUpperCase || !hasLowerCase || !hasNumber || !hasSpecialChar) {
        strengthDiv.textContent = 'Password must be at least 8 characters long and include uppercase, lowercase, number, and special character.';
        strengthDiv.style.color = '#dc3545';
    } else {
        strengthDiv.textContent = 'Password is strong!';
        strengthDiv.style.color = '#28a745';
    }
}

// Form submission validation for signup
function validateForm() {
    const password = document.getElementById('password').value;
    const confirmPassword = document.getElementById('confirm_password').value;
    const minLength = 8;
    const hasUpperCase = /[A-Z]/.test(password);
    const hasLowerCase = /[a-z]/.test(password);
    const hasNumber = /\d/.test(password);
    const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);

    if (password !== confirmPassword) {
        alert('Passwords do not match.');
        return false;
    }

    if (password.length < minLength || !hasUpperCase || !hasLowerCase || !hasNumber || !hasSpecialChar) {
        alert('Please enter a strong password (minimum 8 characters, with uppercase, lowercase, number, and special character).');
        return false;
    }

    return true;
}