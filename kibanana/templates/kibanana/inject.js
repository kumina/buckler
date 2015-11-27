(function() {
    function poll_jquery_and_node() {
        if(typeof $ !== "undefined" && $("div.navbar-collapse").length > 0) {
            $("div.navbar-collapse").append('<ul class="nav navbar-nav">' +
              '<li><a href="{{logout}}"><i class="fa fa-sign-out">' +
              '</i> Logout {{username}}</a></li></ul>');
        }
        else {
            setTimeout(poll_jquery_and_node, 1000);
        }
    }
    function poll_jquery_and_check_settings() {
        if(typeof $ !== "undefined" &&
           $("div.navbar-collapse a[href^='#/settings']").length > 0) {
            $("div.navbar-collapse a[href^='#/settings']").remove();
        }
        else {
            // be aggressive, don't want settings to show briefly
            setTimeout(poll_jquery_and_check_settings, 10);
        }
    }
    poll_jquery_and_node();
    {% if not poweruser %}
    poll_jquery_and_check_settings();
    {% endif %}
})();
