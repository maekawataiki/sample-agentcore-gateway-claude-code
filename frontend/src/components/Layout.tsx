import { NavLink } from "react-router-dom";
import { getUserInfo, logout } from "../auth";
import type { ReactNode } from "react";

export default function Layout({ children }: { children: ReactNode }) {
  const user = getUserInfo();

  return (
    <div className="layout">
      <nav className="sidebar">
        <div className="sidebar-header">
          <h2>Admin Panel</h2>
          <span className="user-badge">{user?.email || user?.username}</span>
        </div>
        <ul className="nav-links">
          <li><NavLink to="/services">Services</NavLink></li>
        </ul>
        <button className="btn btn-secondary logout-btn" onClick={logout}>
          Sign out
        </button>
      </nav>
      <main className="content">{children}</main>
    </div>
  );
}
