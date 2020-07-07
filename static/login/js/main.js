$(document).ready(function () {
    $('#submit').click(function () {

        event.preventDefault(); // prevent PageReLoad

        username = $("#username").val();
        password = $("#password").val();

        $.ajax({
            url: "/signin-password",
            async: true,
            type: "POST",
            data: data,
            contentType: "application/x-www-form-urlencoded",
            beforeSend: function(xhr){
                xhr.setRequestHeader('Authorization', 'Basic ' + btoa(username + ":" + password));
            },
            success: function(response){
                url = window.location.origin + "/redirect?client_id=" + data['client_id'] +
                    "&response_type=" + data['response_type'] + "&redirect_uri=" + data['redirect_uri'] +
                    "&audience=" + data['audience'];
                if(data['scope'] != undefined){
                    url = url + "&scope=" + data['scope'];
                }
                if(data['state'] != undefined){
                    url = url + "&state=" + data['state'];
                }
                window.location.replace(url);
            },
            error: function(response){
                document.getElementById('error').innerText = response.responseJSON['msg'];
                document.getElementById('error').style.display = 'block';
            }
        });
    });
});