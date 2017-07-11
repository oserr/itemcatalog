var logoutBtn = $('#logout-btn');
if (logoutBtn) {
  logoutBtn.click(e => {
    e.preventDefault();
    if (gapi && gapi.auth2) {
      var googleAuth = gapi.auth2.getAuthInstance();
      if (googleAuth) {
        googleAuth.signOut().then(() => {
          console.log('User has been signed out from google signin');
        });
        googleAuth.disconnect();
      }
    }
    $.get('/logout')
      .done(() => { window.location.replace('/'); })
      .fail(() => { console.log('Unable to logout'); });
  });
}
