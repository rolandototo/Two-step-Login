<?php
/**
 * Plugin Name: Two-Step Login
 * Description: Adds a two-step verification to the WordPress login process.
 * Version: 1.0.0
 * Author: Rolando Escobar
 * Author URI: rolandototo.dev
 * License: GPL-2.0+
 * License URI: http://www.gnu.org/licenses/gpl-2.0.txt
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit; // Exit if accessed directly
}

/**
 * Add an extra step to the login process
 */
function two_step_login() {
    // Get the username and password from the first step
    $username = $_POST['log'];
    $password = $_POST['pwd'];

    // If the username and password are correct
    if ( wp_authenticate( $username, $password ) instanceof WP_User ) {
        // Generate a verification code
        $verification_code = mt_rand( 100000, 999999 );

        // Save the verification code to the user's meta
        update_user_meta( get_user_by( 'login', $username )->ID, 'two_step_login_verification_code', $verification_code );

        // Send the verification code to the user's email
        wp_mail( get_user_by( 'login', $username )->user_email, 'Verification Code', 'Your verification code is: ' . $verification_code );

        // Redirect to the second step
        wp_redirect( home_url( '/two-step-login/' ) );
        exit;
    } else {
        // If the username or password is incorrect, redirect to the login page
        wp_redirect( wp_login_url() );
        exit;
    }
}
add_action( 'wp_authenticate', 'two_step_login' );

/**
 * Add a new endpoint to handle the second step of the login process
 */
function two_step_login_endpoint() {
    add_rewrite_endpoint( 'two-step-login', EP_ROOT );
}
add_action( 'init', 'two_step_login_endpoint' );

/**
 * Handle the second step of the login process
 */
function handle_two_step_login() {
    // If the user is not logged in, redirect to the login page
    if ( ! is_user_logged_in() ) {
        wp_redirect( wp_login_url() );
        exit;
    }

    // If the user has already completed the two-step login process, redirect to the home page
    if ( get_user_meta( get_current_user_id(), 'two_step_login_completed', true ) ) {
        wp_redirect( home_url() );
        exit;
    }

    // If the verification code is not submitted, show the verification form
    if ( ! isset( $_POST['verification_code'] ) ) {
        // Get the verification code from the user's meta
        $verification_code = get_user_meta( get_current_user_id(), 'two_step_login_verification_code', true );

        // Show the verification form
        echo '<form method="post">';
        echo '<p>Please enter the verification code sent to your email:</p>';
        echo '<input type="text" name="verification_code" required />';
        echo '<input type="submit" value="Verify" />';
        echo '</form>';

        // If the user has attempted to verify the code and it is incorrect, show an error message
        if ( isset( $_GET['error'] ) && $_GET['error'] == 'incorrect_code' ) {
            echo '<p style="color: red;">The verification code you entered is incorrect.</p>';
        }
    } else {
        // If the verification code is submitted, verify it
        $verification_code = $_POST['verification_code']}

        // Add custom form to second step of login
add_action('login_form', 'custom_login_second_step');
function custom_login_second_step() {
    if (isset($_GET['step']) && $_GET['step'] == 'second') {
        $email = $_GET['email'];
        ?>
        <form method="post">
            <label for="otp"><?php _e('Enter the code you received in your email', 'my-plugin'); ?></label>
            <input type="text" name="otp" id="otp" required>
            <input type="hidden" name="email" value="<?php echo $email; ?>">
            <input type="submit" value="<?php _e('Verify', 'my-plugin'); ?>">
        </form>
        <?php
    }
}

// Verify OTP on login
add_action('wp_authenticate_user', 'verify_login_otp', 10, 2);
function verify_login_otp($user, $password) {
    if (isset($_POST['otp']) && isset($_POST['email'])) {
        $otp = sanitize_text_field($_POST['otp']);
        $email = sanitize_text_field($_POST['email']);

        // Verify OTP against stored value
        $stored_otp = get_user_meta($user->ID, 'login_otp', true);
        if ($otp == $stored_otp) {
            // OTP matches, allow login
            delete_user_meta($user->ID, 'login_otp'); // Remove stored OTP
        } else {
            // Invalid OTP, prevent login
            wp_die(__('Invalid code. Please try again.', 'my-plugin'));
        }
    }
}

// Send OTP email on successful login
add_action('wp_login', 'send_login_otp_email', 10, 2);
function send_login_otp_email($user_login, $user) {
    $email = $user->user_email;
    $otp = generate_otp(); // Function that generates a random OTP

    // Store OTP for verification later
    update_user_meta($user->ID, 'login_otp', $otp);

    // Build email message
    $subject = __('Login Verification Code', 'my-plugin');
    $message = sprintf(__('Your verification code is: %s', 'my-plugin'), $otp);

    // Send email
    wp_mail($email, $subject, $message);

    // Redirect to second step of login
    wp_redirect(add_query_arg('step', 'second', wp_login_url()));
    exit;
}