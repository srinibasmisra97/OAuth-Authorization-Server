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
                url = window.location.origin + "/redirect?";
                for(var key in data){
                    url = url + key + "=" + data[key] + "&";
                }
                url = url + "session=" + response['session'];
                window.location.replace(url);
            },
            error: function(response){
                document.getElementById('error').innerText = response.responseJSON['msg'];
                document.getElementById('error').style.display = 'block';
            }
        });
    });
});