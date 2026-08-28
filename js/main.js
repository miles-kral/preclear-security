document.addEventListener(
    "DOMContentLoaded",
    function () {

        const yearElement =
            document.getElementById(
                "current-year"
            );

        if (yearElement) {
            yearElement.textContent =
                new Date().getFullYear();
        }


        const contactStatus =
            document.getElementById(
                "contact-status"
            );

        if (contactStatus) {

            const params =
                new URLSearchParams(
                    window.location.search
                );

            if (params.get("sent") === "1") {

                contactStatus.innerHTML = `
                    <div
                        class="
                            contact-form-status
                            contact-form-status--success
                        "
                    >
                        Thank you. Your message has been sent to PreClear.
                    </div>
                `;

                contactStatus.scrollIntoView(
                    {
                        behavior: "smooth",
                        block: "center"
                    }
                );

            } else if (
                params.get("error") === "1"
            ) {

                contactStatus.innerHTML = `
                    <div
                        class="
                            contact-form-status
                            contact-form-status--error
                        "
                    >
                        We couldn't send your message.
                        Please try again.
                    </div>
                `;

                contactStatus.scrollIntoView(
                    {
                        behavior: "smooth",
                        block: "center"
                    }
                );
            }
        }


        const mobileNavToggle =
            document.querySelector(
                ".mobile-nav-toggle"
            );

        const siteNav =
            document.querySelector(
                ".site-nav"
            );

        if (
            mobileNavToggle
            && siteNav
        ) {

            mobileNavToggle.addEventListener(
                "click",
                function () {

                    const isOpen =
                        siteNav.classList.toggle(
                            "site-nav--open"
                        );

                    mobileNavToggle.setAttribute(
                        "aria-expanded",
                        String(isOpen)
                    );

                }
            );

            siteNav
                .querySelectorAll("a")
                .forEach(
                    function (link) {

                        link.addEventListener(
                            "click",
                            function () {

                                siteNav.classList.remove(
                                    "site-nav--open"
                                );

                                mobileNavToggle.setAttribute(
                                    "aria-expanded",
                                    "false"
                                );

                            }
                        );

                    }
                );

            window.addEventListener(
                "resize",
                function () {

                    if (window.innerWidth > 960) {

                        siteNav.classList.remove(
                            "site-nav--open"
                        );

                        mobileNavToggle.setAttribute(
                            "aria-expanded",
                            "false"
                        );
                    }

                }
            );


        }

    }
);