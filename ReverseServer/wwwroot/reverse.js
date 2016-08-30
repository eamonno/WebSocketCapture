var socket = null;

function add_response(text) {
    document.getElementById("responses").innerHTML += "<li>" + text + "</li>"; 
}

function send_request() {
    socket.send(document.getElementById("forwardtext").value);
}

function check_connection() {
    if (!socket || socket.readyState == WebSocket.CLOSED) {
        document.getElementById("connectionstatus").innerHTML = "Not Connected";
        //socket = new WebSocket("ws://" + window.location.hostname + ":5656");
        socket = new WebSocket("ws://localhost:5656/reverse");

        // Anytime the server sends a message, update the page appropriately
        socket.onmessage = function (e) {
            add_response(e.data);
        };

        socket.onopen = function () {
            document.getElementById("connectionstatus").innerHTML = "Connected";
        };

        socket.onclose = function () {
            document.getElementById("connectionstatus").innerHTML = "Not Connected";
        };
    }
}

