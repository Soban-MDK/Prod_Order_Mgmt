const container = document.getElementById('container');

if (window.location.pathname === '/signup') {
    container.classList.add('right-panel-active');
} else if (window.location.pathname === '/signin') {
    container.classList.remove('right-panel-active');
}
