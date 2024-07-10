import { createBrowserRouter, RouterProvider, } from "react-router-dom";
import { Chat, Login, Signup } from "./Screens";
import { SocketContextProvider } from "./context/SocketContext";


const router = createBrowserRouter([
  {
    path: "/login",
    element: <Login />
  },
  {
    path: "/signup",
    element: <Signup />
  },
  {
    path: "/chat",
    element: <Chat />
  },
]);

function App() {

  return (
    <>
      <SocketContextProvider>
        <RouterProvider router={router} />
      </SocketContextProvider>
    </>
  )
}

export default App;
