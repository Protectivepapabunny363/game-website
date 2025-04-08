// Configuration
const API_URL = 'http://localhost:5000/api';
const games = [
    "PapaLouie2.swf", "PapaLouie3.swf", "cactusmccoy.swf", "cactusmccoy2.swf",
    "jacksmith.swf", "papalouie_v2.swf", "papasbakeria.swf", "papascupcakeria.swf",
    "papasdonuteria.swf", "papasfreezeria.swf", "papashotdoggeria.swf", "papaspancakeria.swf",
    "papaspastaria.swf", "papasscooperia_v102.swf", "papassushiria.swf", "papastacomia.swf",
    "papaswingeria.swf", "rockgarden_v2.swf", "snjmidnightmarch.swf", "steakandjake_freeversion.swf"
];

const gameLabels = [
    "Papa Louie 2", "Papa Louie 3", "Cactus McCoy", "Cactus McCoy 2",
    "JackSmith", "Papa Louie: When Pizzas Attack", "Papa's Bakeria", "Papa's Cupcakeria",
    "Papa's Donuteria", "Papa's Freezeria", "Papa's Hot Doggeria", "Papa's Pancakeria",
    "Papa's Pastaria", "Papa's Scooperia", "Papa's Sushiria", "Papa's Taco Mia",
    "Papa's Wingeria", "Rock Garden", "Steak and Jake: Midnight March", "Steak and Jake"
];

// Initialize when home.html loads
if (window.location.pathname.endsWith('home.html') || 
    window.location.pathname === '/') {
    document.addEventListener('DOMContentLoaded', () => {
        initializeHomePage();
        checkLoginStatus();
    });
}

function initializeHomePage() {
    // Setup featured game
    const featuredContainer = document.getElementById('featured-game-container');
    const randomIndex = Math.floor(Math.random() * games.length);
    featuredContainer.innerHTML = `
        <img src="images/${games[randomIndex].replace(".swf", ".jpg")}" alt="${gameLabels[randomIndex]}" class="game-image">
        <h3>${gameLabels[randomIndex]}</h3>
        <button onclick="launchGame('${games[randomIndex]}')">Play Now</button>
    `;

    // Setup game grid
    const gridContainer = document.getElementById('game-grid');
    games.forEach((game, index) => {
        const gameDiv = document.createElement('div');
        gameDiv.classList.add('game-card');
        gameDiv.onclick = () => launchGame(game);
        
        const img = document.createElement('img');
        img.src = `images/${game.replace(".swf", ".jpg")}`;
        img.alt = gameLabels[index];
        img.classList.add('game-image');
        
        const title = document.createElement('h3');
        title.textContent = gameLabels[index];
        
        gameDiv.appendChild(img);
        gameDiv.appendChild(title);
        gridContainer.appendChild(gameDiv);
    });

    // Setup grid toggle
    document.getElementById('toggle-grid').addEventListener('click', function() {
        gridContainer.classList.toggle('grid-expanded');
        this.textContent = gridContainer.classList.contains('grid-expanded') ? 
            "Shrink Grid" : "Expand Grid";
    });
}

// Auth functions
async function login() {
    const username = document.getElementById('login-username').value;
    const password = document.getElementById('login-password').value;
    
    if (!username || !password) {
        alert('Please enter both username and password');
        return;
    }
    
    try {
        const response = await fetch(`${API_URL}/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            localStorage.setItem('playerpilot_token', data.token);
            updateLoginStatus(true);
            alert(`Welcome back! Current streak: ${data.user.loginStreak} days`);
        } else {
            alert(data.error || 'Login failed');
        }
    } catch (err) {
        console.error('Login error:', err);
        alert('Network error - please try again');
    }
}

async function register() {
    const username = document.getElementById('register-username').value;
    const email = document.getElementById('register-email').value;
    const password = document.getElementById('register-password').value;
    
    if (!username || !password) {
        alert('Username and password are required');
        return;
    }
    
    try {
        const response = await fetch(`${API_URL}/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, email, password })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            localStorage.setItem('playerpilot_token', data.token);
            updateLoginStatus(true);
            hideRegisterModal();
            alert('Registration successful!');
        } else {
            alert(data.error || 'Registration failed');
        }
    } catch (err) {
        console.error('Registration error:', err);
        alert('Network error - please try again');
    }
}

function logout() {
    localStorage.removeItem('playerpilot_token');
    updateLoginStatus(false);
    alert('Logged out successfully');
}

function checkLoginStatus() {
    const token = localStorage.getItem('playerpilot_token');
    updateLoginStatus(!!token);
    if (token) fetchUserData();
}

function updateLoginStatus(isLoggedIn) {
    const loginSection = document.getElementById('login-section');
    const userSection = document.getElementById('user-section');
    
    if (isLoggedIn) {
        loginSection.style.display = 'none';
        userSection.style.display = 'flex';
    } else {
        loginSection.style.display = 'flex';
        userSection.style.display = 'none';
    }
}

async function fetchUserData() {
    const token = localStorage.getItem('playerpilot_token');
    if (!token) return;
    
    try {
        const response = await fetch(`${API_URL}/user`, {
            headers: { 'x-auth-token': token }
        });
        
        if (response.ok) {
            const data = await response.json();
            document.getElementById('user-greeting').textContent = `Welcome, ${data.user.username}!`;
            document.getElementById('user-streak').textContent = `Login Streak: ${data.user.loginStreak} days`;
        } else if (response.status === 401) {
            // Token is invalid, force logout
            logout();
        }
    } catch (err) {
        console.error('Failed to fetch user data:', err);
    }
}

// Game functions
function launchGame(gameFile) {
    window.location.href = `games.html?game=${encodeURIComponent(gameFile)}`;
}

// Modal functions
function showRegisterModal() {
    document.getElementById('register-modal').style.display = 'block';
}

function hideRegisterModal() {
    document.getElementById('register-modal').style.display = 'none';
    // Clear form
    document.getElementById('register-username').value = '';
    document.getElementById('register-email').value = '';
    document.getElementById('register-password').value = '';
}

// Close modal when clicking outside of it
window.addEventListener('click', (event) => {
    const modal = document.getElementById('register-modal');
    if (event.target === modal) {
        hideRegisterModal();
    }
});

// High score functions
async function submitHighScore(game, score) {
    const token = localStorage.getItem('playerpilot_token');
    if (!token) return;
    
    try {
        await fetch(`${API_URL}/highscore`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'x-auth-token': token
            },
            body: JSON.stringify({ game, score })
        });
    } catch (err) {
        console.error('Failed to save score:', err);
    }
}
