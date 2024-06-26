import React,{ useReducer, useEffect } from 'react';
import axios from 'axios';
import AuthContext from './authContext';
import authReducer from './authReducer';
import setAuthToken from '../../utils/setAuthToken';
import {
     REGISTER_SUCCESS,
     REGISTER_FAIL,
     USER_LOADED,
     AUTH_ERROR,
     LOGIN_SUCCESS,
     LOGIN_FAIL,
     LOGOUT,
     CLEAR_ERRORS
} from '../types';

const AuthState = props => {
    const initialState = {
        token: localStorage.getItem('token'),
        isAuthenticated: null,
        loading: true,
        user: null,
        error: null,
    }; 

    const [state, dispatch] = useReducer(authReducer, initialState);

    useEffect(() => {
        loadUser();
      }, []); // 空数组作为依赖项，确保只在组件挂载时调用一次
    
    // Load User
    const loadUser = async () => {
        if (state.isAuthenticated) {
            return;
        }

        const token = localStorage.getItem('token');
        if (token) {
            setAuthToken(token);
        }
        try {
            const res = await axios.get('/api/auth');
            dispatch({
                type: USER_LOADED, 
                payload: res.data
            });
        } catch (err) {
                dispatch({ type: AUTH_ERROR })
        }
    }

    // Register User
    const register = async formData => {
        const config = {
            headers: {
                'Content-Type' : 'application/json'
            }
        };    

        try {
            const res = await axios.post('/api/users', formData, config);  
            dispatch({ 
                type: REGISTER_SUCCESS,
                payload: res.data
            });
            localStorage.setItem('token', res.data.token);
            console.log(state);
            console.log(localStorage.getItem('token'));
            await loadUser();
        } catch (err) {
                dispatch({
                    type: REGISTER_FAIL,
                    payload: err.response.data.msg
                 });
        }
}
    // Login User
    const login = () => console.log('login')

    // Logout
    const logout = () => console.log('logout')

    // Clear Errors
    const clearErrors = () => console.log('clearErrors')
        //dispatch({ type: CLEAR_ERRORS });

    return (
        <AuthContext.Provider
          value={{
            token:state.token,
            isAuthenticated:state.isAuthenticated,
            loading:state.loading,
            user:state.user,
            error:state.error,
            register,
            loadUser,
            login,
            logout,
            clearErrors
         }}>
            { props.children }
        </AuthContext.Provider>
    )
};

export default AuthState;