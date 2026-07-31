import { createBrowserRouter } from "react-router-dom";
import AuthGuard from "../features/auth/AuthGuard";
import LoginPage from "../features/auth/LoginPage";
import AppLayout from "../layouts/AppLayout";
import HomePage from "../pages/HomePage";
import InterfaceEditorPage from "../pages/InterfaceEditorPage";
import NotFoundPage from "../pages/NotFoundPage";

export const router = createBrowserRouter([
  { path: "/login", element: <LoginPage /> },
  {
    element: <AuthGuard />,
    children: [
      {
        element: <AppLayout />,
        children: [
          { path: "/", element: <HomePage /> },
          { path: "/interfaces/:id", element: <InterfaceEditorPage /> },
          { path: "*", element: <NotFoundPage /> },
        ],
      },
    ],
  },
]);
