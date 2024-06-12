import Box from "@mui/material/Box";
import Button from "@mui/material/Button";
import TextField from "@mui/material/TextField";
import Typography from "@mui/material/Typography";
import axios from "axios";
import { debounce } from "lodash";
import { useEffect, useState } from "react";
import { useForm } from "react-hook-form";
import { Link, useNavigate } from "react-router-dom";
import "./Login.scss";

const Login = () => {
  const navigate = useNavigate();
  const [errorLogin, setErrorLogin] = useState(false);
  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm();

  useEffect(() => {
    const user = localStorage.getItem("user");
    if (user) {
      navigate("/home");
    }
  }, [navigate]);
  const debouncedOnSubmit = debounce(async (data) => {
    try {
      const message = await axios.post("http://localhost:9999/api/login", {
        id: data.username,
        password: data.password,
      });
      let user = message.data.user;
      let token = message.data.token;
      localStorage.setItem("user", JSON.stringify(user));
      localStorage.setItem("token", JSON.stringify(token))
      navigate("/home");
    } catch (error) {
      console.log(error);
      setErrorLogin(true);
    }
  }, 1000); // Thời gian chờ debounce, ở đây là 500 miliseconds

  const onSubmit = (data) => {
    debouncedOnSubmit(data);
  };

  return (
    <div className='wrapper-login'>
      <img
        src='https://res.cloudinary.com/dtxh1xgnb/image/upload/v1714925660/332918529_521994923397551_6382961812691026835_n_xf06zm.jpg'
        alt=''
      />
      <div className='login'>
        <h3>Welcome to PTIT-Connect</h3>
        <Box
          className='form-login'
          component='form'
          onSubmit={handleSubmit(onSubmit)}
          sx={{
            width: "60%",
            height: "60%",
            margin: "auto",
            padding: "20px",
            borderRadius: "8px",
            boxShadow: "0 4px 8px rgba(0,0,0,0.1)",
            backgroundColor: "white",
          }}>
          <Typography
            style={{ textAlign: "center", fontSize: "2rem", fontWeight: "500" }}
            variant='h5'
            component='div'>
            Sign in Form
          </Typography>
          <TextField
            fullWidth
            label='Username'
            {...register("username", {
              required: "Username is required",
              minLength: {
                value: 3,
                message: "Username must be at least 3 characters",
              },
            })}
            error={Boolean(errors.username)}
            helperText={errors.username?.message}
            margin='normal'
            variant='filled'
          />
          <TextField
            fullWidth
            type='password'
            label='Password'
            {...register("password", {
              required: "Password is required",
              minLength: {
                value: 4,
                message: "Password must be at least 5 characters",
              },
            })}
            error={Boolean(errors.password)}
            helperText={errors.password?.message}
            margin='normal'
            variant='filled'
            sx={{ mt: 1 }}
          />
          <p className={errorLogin ? "error" : "disable"}>
            Tài khoản và mật khẩu không đúng
          </p>
          <Button
            type='submit'
            variant='contained'
            color='primary'
            fullWidth
            sx={{ mt: 1 }}>
            Login
          </Button>
          <Box sx={{ mt: 2, textAlign: "center" }}>
            <Link
              href='#'
              variant='body2'>
              Forgot Password?
            </Link>
            <Box mt={1}>
              <Link to='/register'>Don't have an account? Sign Up</Link>
            </Box>
          </Box>
        </Box>
      </div>
    </div>
  );
};

export default Login;
