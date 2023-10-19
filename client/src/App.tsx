import './App.css';
import { useEffect, useState } from 'react';
import axios, { AxiosError, AxiosRequestConfig } from 'axios';
import { useRecoilState } from 'recoil';
import { accessTokenState } from './recoil';

// axios.defaults.withCredentials = true;

function App() {
  const [email, setEmail] = useState('');
  const [pw, setPw] = useState('');
  const [accessToken, setAccessToken] = useRecoilState(accessTokenState);
  const [logined, setLogined] = useState<boolean>(false);

  const refresh = async () => {
    /** 
     *  refresh하고, access token을 리턴
     */
    try {
      const { data } = await axios.post('refresh/');
      return data?.access_token;
    }
    catch (e) {
      throw (e);
    }
  }

  const authGet = async (token: string, url: string) => {
    /**
     * url과 token이 주어졌을 때, 해당 get 함수를 실행
     */
    const config: AxiosRequestConfig = {
      headers: {
        'Authorization': `Bearer ${token}`
      }
    }
    try {
      const { data } = await axios.get(url, config);
      return data;
    } catch (e) {
      if (e instanceof AxiosError) {
        if (e.response?.status === 401) {
          // need refresh
          try {
            const newToken = await refresh();
            const newConfig: AxiosRequestConfig = {
              headers: {
                'Authorization': `Bearer ${newToken}`
              }
            }
            // original request
            const { data } = await axios.get(url, newConfig);
            setAccessToken(accessToken);
            return data;
          } catch (e) {
            setAccessToken('');
            return { data: '로그인이 필요합니다' };
          }
        } else {
          throw e;
        }
      }
    }
  }

  const handleLogin = async () => {
    try {
      const axiosConfig = {
        headers: {
          "Content-Type": "application/x-www-form-urlencoded"
        }
      }
      const { data } = await axios.post('login/', { 'username': email, 'password': pw }, axiosConfig);
      alert('로그인 성공');
      setAccessToken(data?.access_token);
    }
    catch (e) {
      if (e instanceof AxiosError) {
        if (e.response?.status === 401 || 422) {
          alert('로그인 실패');
        }
      }
      console.log(e);
    }
  }
  const handleLogout = async () => {
    try {
      const { data } = await axios.post('logout/');
      alert('로그아웃 성공');
      setAccessToken('');
    } catch (e) {
      console.log(e);
    }
  };

  const handleAuth = async () => {
    try {
      const { data } = await authGet(accessToken, '/authenticated/');
      console.log(data);
      alert(data);
    }
    catch (e) {
      console.log(e);
      alert('에러 발생');
    }
  }

  const refreshAndSet = async () => {
    try {
      const accessToken = await refresh();
      setAccessToken(accessToken);
    }
    catch (e) {
      setAccessToken('');
    }
  }

  useEffect(() => {
    // refresh or logout
    refreshAndSet();
  }, []);

  useEffect(() => {
    if (accessToken) {
      setLogined(true);
    }
    else {
      setLogined(false);
    }
  }, [accessToken]);

  return (
    <div className='App'>
      {logined ?
        // 로그인 되어 있는 상태
        <div>
          <button onClick={handleLogout}>logout</button> <br />
          <button onClick={handleAuth}>요청1</button>
        </div> :
        // 로그인 안되어 있는 상태
        <div>
          <h4>JWT Service</h4>
          <input type='text' value={email} onChange={(e) => setEmail(e.target.value)} />
          <br />
          <input type='text' value={pw} onChange={(e) => setPw(e.target.value)} />
          <br />
          <button onClick={handleLogin}>login</button>
        </div>}

    </div>
  );
}

export default App;