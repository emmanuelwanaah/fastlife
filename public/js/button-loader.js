(function () {

    'use strict';


    // =========================================================
    // GLOBAL PAGE LOADER
    // =========================================================

    let loader = null;


    // =========================================================
    // CREATE LOADER
    // =========================================================

    function createLoader() {

        if (loader) {
            return loader;
        }


        loader = document.createElement('div');

        loader.id = 'global-page-loader';

        loader.className = `
            fixed
            inset-0
            z-[99999]
            hidden
            items-center
            justify-center
            bg-white/90
            backdrop-blur-sm
            px-5
        `;


        loader.innerHTML = `

            <div class="mx-auto w-full max-w-sm rounded-md border border-blue-300 bg-white p-4 shadow-sm">

                <div class="flex animate-pulse space-x-4">

                    <div class="size-10 rounded-full bg-gray-200"></div>

                    <div class="flex-1 space-y-6 py-1">

                        <div class="h-2 rounded bg-gray-200"></div>

                        <div class="space-y-3">

                            <div class="grid grid-cols-3 gap-4">

                                <div class="col-span-2 h-2 rounded bg-gray-200"></div>

                                <div class="col-span-1 h-2 rounded bg-gray-200"></div>

                            </div>

                            <div class="h-2 rounded bg-gray-200"></div>

                        </div>

                    </div>

                </div>

            </div>

        `;


        document.body.appendChild(loader);

        return loader;
    }


    // =========================================================
    // SHOW
    // =========================================================

    function showLoader() {

        const pageLoader =
            createLoader();


        pageLoader.classList.remove(
            'hidden'
        );


        pageLoader.classList.add(
            'flex'
        );


        document.body.classList.add(
            'overflow-hidden'
        );

    }


    // =========================================================
    // HIDE
    // =========================================================

    function hideLoader() {

        if (!loader) {
            return;
        }


        loader.classList.remove(
            'flex'
        );


        loader.classList.add(
            'hidden'
        );


        document.body.classList.remove(
            'overflow-hidden'
        );

    }


    // =========================================================
    // PAGE INITIALIZATION
    // =========================================================

    function initializeLoader() {

        /*
         * Show loader immediately.
         *
         * This covers the time while the page,
         * CSS, images and JavaScript are loading.
         */

        showLoader();


        /*
         * Hide loader when the entire page has loaded.
         */

        if (
            document.readyState === 'complete'
        ) {

            hideLoader();

        } else {

            window.addEventListener(
                'load',
                function () {

                    hideLoader();

                },
                {
                    once: true
                }
            );

        }

    }


    // =========================================================
    // LINK NAVIGATION
    // =========================================================

    document.addEventListener(
        'click',
        function (event) {

            /*
             * Find the nearest link.
             */

            const link =
                event.target.closest('a');


            if (!link) {
                return;
            }


            /*
             * Don't interfere with modified clicks.
             *
             * Ctrl + click
             * Cmd + click
             * Shift + click
             * Middle mouse button
             */

            if (
                event.ctrlKey ||
                event.metaKey ||
                event.shiftKey ||
                event.altKey ||
                event.button !== 0
            ) {

                return;

            }


            /*
             * Ignore links without navigation.
             */

            const href =
                link.getAttribute('href');


            if (
                !href ||
                href === '#' ||
                href.startsWith('#')
            ) {

                return;

            }


            /*
             * Ignore JavaScript links.
             */

            if (
                href.startsWith('javascript:')
            ) {

                return;

            }


            /*
             * Ignore downloads.
             */

            if (
                link.hasAttribute('download')
            ) {

                return;

            }


            /*
             * Ignore target="_blank".
             */

            if (
                link.target === '_blank'
            ) {

                return;

            }


            /*
             * Ignore external websites.
             */

            let url;

            try {

                url =
                    new URL(
                        href,
                        window.location.href
                    );

            } catch {

                return;

            }


            if (
                url.origin !==
                window.location.origin
            ) {

                return;

            }


            /*
             * Same-page URL.
             */

            if (
                url.href ===
                window.location.href
            ) {

                return;

            }


            /*
             * Show loader before navigation.
             */

            showLoader();

        },
        true
    );


    // =========================================================
    // FORM SUBMISSION
    // =========================================================

    document.addEventListener(
        'submit',
        function (event) {

            const form =
                event.target;


            /*
             * Don't interfere with forms that
             * explicitly use AJAX.
             */

            if (
                form.hasAttribute(
                    'data-ajax'
                )
            ) {

                return;

            }


            /*
             * Normal form navigation.
             */

            showLoader();

        },
        true
    );


    // =========================================================
    // BROWSER NAVIGATION
    // =========================================================

    window.addEventListener(
        'beforeunload',
        function () {

            /*
             * Make sure loader is visible
             * while leaving the page.
             */

            showLoader();

        }
    );


    // =========================================================
    // BACK/FORWARD CACHE
    // =========================================================

    window.addEventListener(
        'pageshow',
        function (event) {

            /*
             * When browser restores a page from
             * the back-forward cache, remove loader.
             */

            if (event.persisted) {

                hideLoader();

            }

        }
    );


    // =========================================================
    // PUBLIC API
    // =========================================================

    window.ButtonLoader = {

        show: showLoader,

        hide: hideLoader,

        start: showLoader,

        stop: hideLoader,

        forceStop: hideLoader

    };


    // =========================================================
    // START
    // =========================================================

    if (
        document.readyState === 'loading'
    ) {

        document.addEventListener(
            'DOMContentLoaded',
            initializeLoader,
            {
                once: true
            }
        );

    } else {

        initializeLoader();

    }

})();