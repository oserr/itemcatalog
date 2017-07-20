function onSignIn(googleUser) {
  console.log('called onSignIn()');
  var profile = googleUser.getBasicProfile();
  var id_token = googleUser.getAuthResponse().id_token;
  $.post('/glogin', 'token=' + id_token)
    .done((data, textStatus, xhr) => {
      if (xhr.status === 200) {
        console.log('redirecting to main page');
        window.location.replace('/');
      } else {
        console.log('Received non-success response with status=' + xhr.status);
        $('#err-msg').html('<p>Unable to signin via Google</p>');
      }
    })
    .fail((data, textStatus, err) => {
        console.log('Post request failed with error ' + err);
        $('#err-msg').html('<p>Unable to signin via Google</p>');
    });
}

$('#register-div a:first').click(e => {
  console.log('entered register handler');
  e.preventDefault();
  $('#google-button').addClass('hidden');
  $('#register-div').addClass('hidden');
  $('#login-div').removeClass('hidden');
  $('form').attr('action', '/register');
  $('form p:first').text('Register with your email');
  $('button').text('Register');
});

$('#login-div a:first').click(e => {
  console.log('entered login handler');
  e.preventDefault();
  $('#google-button').removeClass('hidden');
  $('#register-div').removeClass('hidden');
  $('#login-div').addClass('hidden');
  $('form').attr('action', '/login');
  $('form p:first').text('Log in with your email');
  $('button').text('Login');
});
