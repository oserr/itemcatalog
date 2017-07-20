// Hide the new category text input when the page is ready if other is
// not selected. This should always be the case, except when there are
// no categories.
$('document').ready(() => {
  let newCat = $('#newcategory-row');
  if ($('select').val() === 'other') {
    newCat.show();
  } else {
    newCat.val('');
    newCat.hide();
  }
});

// Show the text input for a new category if the user wants to create a new
// category, otherwise hide it.
$('select').change(() => {
  let newCat = $('#newcategory-row');
  if ($('select').val() === 'other') {
    newCat.show();
  } else {
    newCat.val('');
    newCat.hide();
  }
});
