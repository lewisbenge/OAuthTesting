using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using Windows.ApplicationModel;
using Windows.ApplicationModel.Activation;
using Windows.Foundation;
using Windows.Foundation.Collections;
using Windows.Security.Authentication.Web;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using Windows.Storage.Streams;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
using Windows.UI.Xaml.Controls.Primitives;
using Windows.UI.Xaml.Data;
using Windows.UI.Xaml.Input;
using Windows.UI.Xaml.Media;
using Windows.UI.Xaml.Navigation;

// The Blank Application template is documented at http://go.microsoft.com/fwlink/?LinkId=234227

namespace DropBox
{
    /// <summary>
    /// Provides application-specific behavior to supplement the default Application class.
    /// </summary>
    sealed partial class App : Application
    {
        private string _token = null;
        private const string  AppKey = "79ouoo4g483jmnz";
        private const string AppSecret = "z5odpncw8jhzgk9";
        private string _getResponse;

        /// <summary>
        /// Initializes the singleton application object.  This is the first line of authored code
        /// executed, and as such is the logical equivalent of main() or WinMain().
        /// </summary>
        public App()
        {
            this.InitializeComponent();
            this.Suspending += OnSuspending;
        }

        /// <summary>
        /// Invoked when the application is launched normally by the end user.  Other entry points
        /// will be used when the application is launched to open a specific file, to display
        /// search results, and so forth.
        /// </summary>
        /// <param name="args">Details about the launch request and process.</param>
        protected override async void OnLaunched(LaunchActivatedEventArgs args)
        {
            // Do not repeat app initialization when already running, just ensure that
            // the window is active
            if (args.PreviousExecutionState == ApplicationExecutionState.Running)
            {
                Window.Current.Activate();
                return;
            }

            if (args.PreviousExecutionState == ApplicationExecutionState.Terminated)
            {
                //TODO: Load state from previously suspended application
            }

            // Create a Frame to act navigation context and navigate to the first page
            var rootFrame = new Frame();
            if (!rootFrame.Navigate(typeof(MainPage)))
            {
                throw new Exception("Failed to create initial page");
            }

            // Place the frame in the current Window and ensure that it is active
            Window.Current.Content = rootFrame;
            Window.Current.Activate();

            if(String.IsNullOrEmpty(_token)){
                
                //
                // Acquiring a request token
                //
                TimeSpan SinceEpoch = (DateTime.Now - new DateTime(1970, 1, 1, 0, 0, 0, 0).ToLocalTime());
                Random Rand = new Random();
                String FlickrUrl = "https://api.dropbox.com/1/oauth/request_token";
                Int32 Nonce = Rand.Next(1000000000);
                //
                // Compute base signature string and sign it.
                //    This is a common operation that is required for all requests even after the token is obtained.
                //    Parameters need to be sorted in alphabetical order
                //    Keys and values should be URL Encoded.
                //
                String SigBaseStringParams = "oauth_timestamp=" + Math.Round(SinceEpoch.TotalSeconds); 
                SigBaseStringParams += "&" + "oauth_signature_method=HMAC-SHA1";
                SigBaseStringParams += "&" + "oauth_nonce=" + Nonce.ToString();
                SigBaseStringParams += "&" + "oauth_version=1.0";
                SigBaseStringParams += "&" + "oauth_consumer_key=" + AppKey;
                SigBaseStringParams += "&" + "oauth_callback=" + Uri.EscapeUriString(WebAuthenticationBroker.GetCurrentApplicationCallbackUri().ToString());
                String SigBaseString = "GET&";
                SigBaseString += Uri.EscapeDataString(FlickrUrl) + "&" + SigBaseStringParams;

                IBuffer KeyMaterial = CryptographicBuffer.ConvertStringToBinary(AppSecret + "&", BinaryStringEncoding.Utf8);
                MacAlgorithmProvider HmacSha1Provider = MacAlgorithmProvider.OpenAlgorithm("HMAC_SHA1");
                CryptographicKey MacKey = HmacSha1Provider.CreateKey(KeyMaterial);
                IBuffer DataToBeSigned = CryptographicBuffer.ConvertStringToBinary(SigBaseString, BinaryStringEncoding.Utf8);
                IBuffer SignatureBuffer = CryptographicEngine.Sign(MacKey, DataToBeSigned);
                String Signature = CryptographicBuffer.EncodeToBase64String(SignatureBuffer);

                FlickrUrl += "?" + SigBaseStringParams + "&oauth_signature=" + Signature;
                SendData(FlickrUrl);


                if (_getResponse != null)
                {
                    String oauth_token = null;
                    String oauth_token_secret = null;
                    String[] keyValPairs = _getResponse.Split('&');

                    for (int i = 0; i < keyValPairs.Length; i++)
                    {
                        String[] splits = keyValPairs[i].Split('=');
                        switch (splits[0])
                        {
                            case "oauth_token":
                                oauth_token = splits[1];
                                break;
                            case "oauth_token_secret":
                                oauth_token_secret = splits[1];
                                break;
                        }
                    }

                    if (oauth_token != null)
                    {

                        FlickrUrl = "https://www.dropbox.com/1/oauth/authorize?oauth_token=" + oauth_token;
                        System.Uri StartUri = new Uri(FlickrUrl);
                        System.Uri EndUri = WebAuthenticationBroker.GetCurrentApplicationCallbackUri();

                        

                        WebAuthenticationResult WebAuthenticationResult = await WebAuthenticationBroker.AuthenticateAsync(
                                                                WebAuthenticationOptions.None,
                                                                StartUri,
                                                                EndUri);
                        if (WebAuthenticationResult.ResponseStatus == WebAuthenticationStatus.Success)
                        {
                          
                        }
                        else if (WebAuthenticationResult.ResponseStatus == WebAuthenticationStatus.ErrorHttp)
                        {
                            
                        }
                        else
                        {
                           
                        }
                    }
                }
            
            }
        }

        private async void SendData(String Url)
        {
            try
            {
                HttpWebRequest Request = (HttpWebRequest)WebRequest.Create(Url);
                Request.Method = "GET";
                HttpWebResponse Response = (HttpWebResponse)await Request.GetResponseAsync();
                StreamReader ResponseDataStream = new StreamReader(Response.GetResponseStream());
               _getResponse = ResponseDataStream.ReadToEnd();
            }
            catch (Exception Err)
            {
                //rootPage.NotifyUser("Error posting data to server." + Err.Message, NotifyType.StatusMessage);
            }
        }

        /// <summary>
        /// Invoked when application execution is being suspended.  Application state is saved
        /// without knowing whether the application will be terminated or resumed with the contents
        /// of memory still intact.
        /// </summary>
        /// <param name="sender">The source of the suspend request.</param>
        /// <param name="e">Details about the suspend request.</param>
        private void OnSuspending(object sender, SuspendingEventArgs e)
        {
            var deferral = e.SuspendingOperation.GetDeferral();
            //TODO: Save application state and stop any background activity
            deferral.Complete();
        }
    }
}
