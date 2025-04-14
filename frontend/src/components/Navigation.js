import React from "react";
import { Link, useLocation } from "react-router-dom";
import AuthService from "../utils/AuthService";
import {
  NavigationMenu,
  NavigationMenuContent,
  NavigationMenuItem,
  NavigationMenuLink,
  NavigationMenuList,
  NavigationMenuTrigger,
  navigationMenuTriggerStyle,
} from "../components/ui/navigation-menu";
import { Button } from "../components/ui/button";

const Navigation = ({ setIsAuthenticated }) => {
  const location = useLocation();

  const handleLogout = () => {
    AuthService.logout();
    setIsAuthenticated(false);
  };

  const isActive = (path) => location.pathname === path;

  return (
    <div className="bg-primary text-white w-full">
      <div className="container mx-auto px-4 py-3">
        <div className="flex justify-between items-center">
          <div className="flex items-center space-x-2">
            <Link to="/" className="text-xl font-bold text-white">
              Network IDS
            </Link>

            <NavigationMenu className="ml-8">
              <NavigationMenuList>
                <NavigationMenuItem>
                  <Link to="/" legacyBehavior passHref>
                    <NavigationMenuLink
                      className={`${navigationMenuTriggerStyle()} ${
                        isActive("/") ? "bg-primary-foreground/20" : ""
                      }`}
                    >
                      Dashboard
                    </NavigationMenuLink>
                  </Link>
                </NavigationMenuItem>
                <NavigationMenuItem>
                  <Link to="/traffic" legacyBehavior passHref>
                    <NavigationMenuLink
                      className={`${navigationMenuTriggerStyle()} ${
                        isActive("/traffic") ? "bg-primary-foreground/20" : ""
                      }`}
                    >
                      Traffic Monitor
                    </NavigationMenuLink>
                  </Link>
                </NavigationMenuItem>
                <NavigationMenuItem>
                  <Link to="/alerts" legacyBehavior passHref>
                    <NavigationMenuLink
                      className={`${navigationMenuTriggerStyle()} ${
                        isActive("/alerts") ? "bg-primary-foreground/20" : ""
                      }`}
                    >
                      Alerts
                    </NavigationMenuLink>
                  </Link>
                </NavigationMenuItem>
                <NavigationMenuItem>
                  <Link to="/settings" legacyBehavior passHref>
                    <NavigationMenuLink
                      className={`${navigationMenuTriggerStyle()} ${
                        isActive("/settings") ? "bg-primary-foreground/20" : ""
                      }`}
                    >
                      Settings
                    </NavigationMenuLink>
                  </Link>
                </NavigationMenuItem>
              </NavigationMenuList>
            </NavigationMenu>
          </div>

          <Button variant="outline" onClick={handleLogout}>
            Logout
          </Button>
        </div>
      </div>
    </div>
  );
};

export default Navigation;
