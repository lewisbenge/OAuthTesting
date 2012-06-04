using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using DropBox.Services;
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
        private string _postResponse;

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

            var authentication = new Authentication(AppKey, AppSecret);
            var token = await authentication.RequestToken("https://api.dropbox.com/1/oauth/request_token", WebAuthenticationBroker.GetCurrentApplicationCallbackUri().ToString());

            if(token != null){

               
                

                           var url = "https://www.dropbox.com/1/oauth/authorize?oauth_token=" + token.Key + "&oauth_callback="+ WebAuthenticationBroker.GetCurrentApplicationCallbackUri();
                           System.Uri StartUri = new Uri(url);
                           
                        //DebugPrint("Navigating to: " + TwitterUrl);

                        WebAuthenticationResult WebAuthenticationResult = await WebAuthenticationBroker.AuthenticateAsync(
                                                                WebAuthenticationOptions.None,
                                                                StartUri);
                        if (WebAuthenticationResult.ResponseStatus == WebAuthenticationStatus.Success)
                        {
                            //ms-app://s-1-15-2-1337643465-2015727581-969725645-1827392481-3205445599-2531636465-749772993/?uid=22699404&oauth_token=jmkcwhuk7q32jy0
                            authentication.GetAccessToken("https://api.dropbox.com/1/oauth/access_token?oauth_token=" + token.Key, token.Key, token.Secret);
                        }
                        else if (WebAuthenticationResult.ResponseStatus == WebAuthenticationStatus.ErrorHttp)
                        {
                            //OutputToken("HTTP Error returned by AuthenticateAsync() : " + WebAuthenticationResult.ResponseErrorDetail.ToString());
                        }
                        else
                        {
                            // OutputToken("Error returned by AuthenticateAsync() : " + WebAuthenticationResult.ResponseStatus.ToString());
                        }
                    
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
