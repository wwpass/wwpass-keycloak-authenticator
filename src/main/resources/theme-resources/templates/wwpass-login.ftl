<#import "template.ftl" as layout>
<@layout.registrationLayout; section>
    <#if section = "title">
        ${msg("loginTitle",realm.name)}
    <#elseif section = "header">
        <link href="${url.resourcesPath}/style/wwpass-style.css" rel="stylesheet">
        <span class="heading heading--h2 heading--light heading--center heading--marginBottom-0 qrcode-heading">${msg("wwpass-scan-qr-code")}</span>
        <br>
        <span class="text text--marginTop-0 text--center qrcode-heading">with WWPass<sup class="text__sup">TM</sup> Key app to log in</span>
    <#elseif section = "form">
        <div id="wwpass-auth">
            <div class="loginMain__code-qr qrtap" id="qrcode">
                <canvas width="256" height="256"></canvas>
            </div>
            <div id="passkey" style="display:none">
                <button class="button button--action">Log in with WWPass Key</button>
            </div>

            <div class="hr"></div>
            <p class="text text--sm text--center text--marginBottom-15">Download WWPass<sup class="text__sup">TM</sup> Key app from</p>
            <div class="buttons">
                <a class="button button--store button--store-ios" href="https://itunes.apple.com/us/app/wwpass-passkey-lite/id984532938">AppStore</a>
                <a class="button button--store button--store-google" href="https://play.google.com/store/apps/details?id=com.wwpass.android.passkey">Google Play</a>
            </div>
        </div>
        <script type="text/javascript">
            window.onload = function () {
                if (document.getElementById('qrcode')) {
                    WWPass.authInit({
                        qrcode: '#qrcode',
                        passkey: '#passkey',
                        forcePasskeyButton: false,
                        callbackURL: '../../broker/${providerID?no_esc}/endpoint?state=${state}',
                        ticketURL: '../../wwpass-ticket?config=' + encodeURI('${providerID?no_esc}'),
                        uiCallback: function (event) {
                            const headings = document.querySelectorAll(`.qrcode-heading`);
                            if (headings) {
                                for (let i = 0; i < headings.length; i++) {
                                    if (event.button) headings[i].style.display = 'none';
                                    if (event.qrcode) headings[i].style.display = null;
                                }
                            }
                        }
                    });
                }
            };
        </script>
        <script type="text/javascript" src="${url.resourcesPath}/wwpass-frontend.min.js"></script>
    </#if>
</@layout.registrationLayout>