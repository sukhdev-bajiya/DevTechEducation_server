function emailTemplate(name, username, password) {
  return `<div><p><b> Dear ${name} </b>,</p>
<p>Greetings from <b> <i> Dev Tech Education! </i> </b> </p>
<p>Hope you are doing well,</p>
<p>Please find below the important details regarding your education journey</p>

<p>Important Details:-</p>
Course Platform Username : <b> ${username} </b><br>
Course Platform Password : <b> ${password} </b> <br>
Course Platform Link : <a href="https://devtecheducation.netlify.app" target="_blank" >https://devtecheducation.netlify.app</a><br>
</p>

<p>You can write to us at <a href="mailto:devtecheducation@gmail.com" target="_blank">devtecheducation@gmail.com</a> for any additional information or queries</p>

<p>Happy Learning!</p>

<p>Regards,<br>
<b><i> Team Dev Tech Education </i></b></p>
</div>`;
}
module.exports[emailTemplate];
