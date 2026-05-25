// ============================================================
//  PASSWORD UTILITIES
// ============================================================
function togglePassword(fieldId, iconId) {
    const field = document.getElementById(fieldId);
    const icon  = document.getElementById(iconId);
    if (!field || !icon) return;

    if (field.type === 'password') {
        field.type = 'password' === field.type ? 'text' : 'password';
        field.type = 'text';
        icon.classList.replace('fa-eye', 'fa-eye-slash');
    } else {
        field.type = 'password';
        icon.classList.replace('fa-eye-slash', 'fa-eye');
    }
}

function checkPasswordStrength(password) {
    const fill = document.getElementById('strengthFill');
    const text = document.getElementById('strengthText');
    if (!fill || !text) return;

    let strength = 0;
    let label    = '';
    let color    = '';

    if (password.length >= 6)  strength++;
    if (password.length >= 10) strength++;
    if (/[A-Z]/.test(password))    strength++;
    if (/[0-9]/.test(password))    strength++;
    if (/[^A-Za-z0-9]/.test(password)) strength++;

    const levels = [
        { pct: '0%',   label: '',         color: '' },
        { pct: '25%',  label: 'Weak',     color: '#ef4444' },
        { pct: '50%',  label: 'Fair',     color: '#f59e0b' },
        { pct: '75%',  label: 'Good',     color: '#22d3ee' },
        { pct: '90%',  label: 'Strong',   color: '#22c55e' },
        { pct: '100%', label: 'Very Strong', color: '#22c55e' },
    ];

    const lvl = levels[Math.min(strength, 5)];
    fill.style.width      = lvl.pct;
    fill.style.background = lvl.color;
    text.textContent      = lvl.label;
    text.style.color      = lvl.color;

    // Also validate confirm password match
    const confirm = document.getElementById('confirm_password');
    if (confirm && confirm.value) checkPasswordMatch();
}

function checkPasswordMatch() {
    const pass    = document.getElementById('password');
    const confirm = document.getElementById('confirm_password');
    const ind     = document.getElementById('matchIndicator');
    if (!pass || !confirm || !ind) return;

    if (confirm.value === '') {
        ind.innerHTML = '';
        return;
    }

    if (pass.value === confirm.value) {
        ind.innerHTML = `<span style="color:#22c55e"><i class="fas fa-circle-check me-1"></i>Passwords match</span>`;
    } else {
        ind.innerHTML = `<span style="color:#ef4444"><i class="fas fa-circle-xmark me-1"></i>Passwords do not match</span>`;
    }
}

// Attach confirm password listener
document.addEventListener('DOMContentLoaded', () => {
    const confirm = document.getElementById('confirm_password');
    if (confirm) confirm.addEventListener('input', checkPasswordMatch);

    // Auto dismiss alerts
    setTimeout(() => {
        document.querySelectorAll('.flash-container .alert').forEach(el => {
            el.classList.remove('show');
            setTimeout(() => el.remove(), 300);
        });
    }, 5000);

    // Navbar scroll effect
    window.addEventListener('scroll', () => {
        const nav = document.getElementById('mainNav');
        if (!nav) return;
        if (window.scrollY > 50) {
            nav.style.background = 'rgba(10, 15, 30, 0.97)';
        } else {
            nav.style.background = 'rgba(10, 15, 30, 0.85)';
        }
    });
});