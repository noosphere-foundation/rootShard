var ip = "http://192.168.0.12:8081"

function generateCaptcha() {
  $.ajax({
    method: "POST",
    url: ip + "/generate-captcha",
  }).done(function(captcha) {
    $("#captcha-img").attr("src", captcha);
  });
}

$("#sign-up-form").on("submit", (e) => {
  e.preventDefault();
  e.stopPropagation();

  var emailExists = false;

  $.when($.ajax({
    method: "POST",
    url: ip + "/check-if-email-exists",
    data: "email=" + $("#emailSignUp").val().toLowerCase(),
  })
    .done(function(msg) {
      if (msg.length === 0) { return }
      emailExists = true;
      alert("User with such email already exists!");
      $("#emailSignUp").val("");
      $("#emailSignUp").focus();
    }))
      .then(function(){
        if (emailExists) { return }
        var bits = sjcl.hash.sha256.hash($("#passwordSignUp").val());
        var passwordHash = sjcl.codec.hex.fromBits(bits);

        $.ajax({
          method: "POST",
          url: ip + "/sign-up",
          data: "firstName=" + $("#firstName").val() + "&lastName=" + $("#lastName").val() + "&email="
            + $("#emailSignUp").val().toLowerCase() + "&password=" + passwordHash
        })
          .done(function(msg) {
            if (msg.length > 0) {
              alert(msg);
            } else {
              window.location = ip + "/registered";
            }
          });
      });
});

$("#form-signin").on("submit", (e) => {
  e.preventDefault();
  e.stopPropagation();

  var bits = sjcl.hash.sha256.hash($("#passwordSignIn").val());
  var passwordHash = sjcl.codec.hex.fromBits(bits);

  $.ajax({
    method: "POST",
    url: ip + "/login",
    data: "email=" + $("#emailSignIn").val().toLowerCase() + "&password=" + passwordHash + "&captcha="
      + $("#captcha-input").val()
  })
    .done(function(msg) {
      if (msg === "0" || msg === "1" || msg === "2") {
        if (msg === "0") {
          alert("Incorrect email or password. Try again!");
          $("#emailSignIn").val("");
          $("#passwordSignIn").val("");
          $("#emailSignIn").focus();
        } else if (msg === "1") {
          alert("Please confirm your email!");
        } else {
          alert("Your captcha solution is incorrect. Please try again!");
          generateCaptcha();
          $("#captcha-input").val("");
          $("#captcha-input").focus();
        }
      } else {
        window.location = ip + "/logged-in?" + msg;
      }
    });
});
