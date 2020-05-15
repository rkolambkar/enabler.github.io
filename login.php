<?php
// Initialize the session
session_start();
 
// Check if the user is already logged in, if yes then redirect him to welcome page
if(isset($_SESSION["loggedin"]) && $_SESSION["loggedin"] === true){
    header("location: dashboard.html");
    exit;
}
 
// Include config file
require_once "config.php";
 
// Define variables and initialize with empty values
$username = $password = "";
$username_err = $password_err = "";
 
// Processing form data when form is submitted
if($_SERVER["REQUEST_METHOD"] == "POST"){
 
    // Check if username is empty
    if(empty(trim($_POST["username"]))){
        $username_err = "Please enter username.";
    } else{
        $username = trim($_POST["username"]);
    }
    
    // Check if password is empty
    if(empty(trim($_POST["password"]))){
        $password_err = "Please enter your password.";
    } else{
        $password = trim($_POST["password"]);
    }
    
    // Validate credentials
    if(empty($username_err) && empty($password_err)){
        // Prepare a select statement
        $sql = "SELECT id, username, password FROM users WHERE username = ?";
        
        if($stmt = mysqli_prepare($link, $sql)){
            // Bind variables to the prepared statement as parameters
            mysqli_stmt_bind_param($stmt, "s", $param_username);
            
            // Set parameters
            $param_username = $username;
            
            // Attempt to execute the prepared statement
            if(mysqli_stmt_execute($stmt)){
                // Store result
                mysqli_stmt_store_result($stmt);
                
                // Check if username exists, if yes then verify password
                if(mysqli_stmt_num_rows($stmt) == 1){                    
                    // Bind result variables
                    mysqli_stmt_bind_result($stmt, $id, $username, $hashed_password);
                    if(mysqli_stmt_fetch($stmt)){
                        if(password_verify($password, $hashed_password)){
                            // Password is correct, so start a new session
                            session_start();
                            
                            // Store data in session variables
                            $_SESSION["loggedin"] = true;
                            $_SESSION["id"] = $id;
                            $_SESSION["username"] = $username;                            
                            
                            // Redirect user to welcome page
                            header("location: dashboard.html");
                        } else{
                            // Display an error message if password is not valid
                            $password_err = "The password you entered was not valid.";
                        }
                    }
                } else{
                    // Display an error message if username doesn't exist
                    $username_err = "No account found with that username.";
                }
            } else{
                echo "Oops! Something went wrong. Please try again later.";
            }

            // Close statement
            mysqli_stmt_close($stmt);
        }
    }
    
    // Close connection
    mysqli_close($link);
}
?>
 
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Login</title>
<link rel="stylesheet" type="text/css" href="Style.css">
<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.css">
</head>
<body class="bod">
	<div class="header">
		<img src="https://app.enablerinteractive.com/assets/images/Enabler_small.png" alt="EnablerInteractive" width="250">
	</div>
	<form method="post" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>">
		<label class = "login" style="top: 16vw; left: 40vw;">Login</label>
		
		<div class="form-group <?php echo (!empty($username_err)) ? 'has-error' : ''; ?>">
			<label class="Font" style="top: 25vw; left: 40vw;"><b>Username:</b></label>
			<input type="text" name="username" style="top:24vw; left:48vw;" value="<?php echo $username; ?>" required>
			<span class="help-block" style="color:#ffa500;"><?php echo $username_err; ?></span>
		</div>
		
		<div class="form-group <?php echo (!empty($password_err)) ? 'has-error' : ''; ?>">
			<label class="Font" style="top: 30vw; left: 40vw;"><b>Password:</b></label>
			<input type="password" name="password" style="top:29vw; left:48vw;" required>
			<span class="help-block" style="color:#ffa500;"><?php echo $password_err; ?></span>
		</div>
		
		<button type="submit" name="action" value="Login" class="login_btn">Login</button>
		<p class="fpsw" style="color: white;">Don't have an account? <a style="color: #ffa500;" href="register.php"> Sign up</a>.<p/>    
		<p class="fpsf" style="color: white;">Forgot password? <a style="color: #ffa500;" href="reset-password.php">Reset now</a>.</p>
	</form>  
</body>
</html>