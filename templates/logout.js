function start() {
  gapi.load('auth2', () => {
    gapi.auth2.init({
      client_id: "1079849348157-0oqrbkk9rj24k79vcni7e2tu8p081t3a.apps.googleusercontent.com",
    });
  });

  var logoutBtn = $('#logout-btn');
  if (logoutBtn) {
    logoutBtn.click(e => {
      e.preventDefault();
      if (gapi && gapi.auth2) {
        var googleAuth = gapi.auth2.getAuthInstance();
        if (googleAuth) {
          googleAuth.signOut().then(() => {
            setTimeout(() => {}, 3000);
          });
          googleAuth.disconnect();
        }
      } else if (!gapi) {
        console.log('gapi is not defined');
      } else {
        console.log('gapi is defined but gapi.auth2 is not');
      }
      $.get('/logout')
        .done(() => { window.location.replace('/'); })
        .fail(() => { console.log('Unable to logout'); });
    });
  }

}
