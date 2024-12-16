document.addEventListener("DOMContentLoaded", function() {
    const button = document.getElementById("button");

    setTimeout(() => {
        button.classList.add("enabled");
    }, 5000);
});