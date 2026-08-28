document.addEventListener('DOMContentLoaded', async () => {
  try {
    const response = await fetch('/session', {
      credentials: 'include'
    });

    if (!response.ok) {
      redirectToLogin();
      return;
    }

    const session = await response.json();

    if (!session.loggedIn) {
      redirectToLogin();
    }

  } catch (error) {
    console.error('❌ Session check failed:', error);
    redirectToLogin();
  }
});

function redirectToLogin() {
  const currentPage =
    window.location.pathname +
    window.location.search +
    window.location.hash;

  window.location.href =
    `/login.html?redirect=${encodeURIComponent(currentPage)}`;
}