window.plausible =
    window.plausible ||
    function() {
        (
            plausible.q =
            plausible.q || []
        ).push(arguments);
    };

plausible.init =
    plausible.init ||
    function(options) {
        plausible.o = options || {};
    };

plausible.init();
