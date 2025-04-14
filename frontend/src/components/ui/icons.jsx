import React from "react";
import { AlertTriangle, CheckCircle } from "lucide-react";

// This file provides icon replacements for Radix UI icons using Lucide React
// which is already available in the dependencies

export const ExclamationTriangleIcon = (props) => {
  return <AlertTriangle {...props} />;
};

export const CheckCircledIcon = (props) => {
  return <CheckCircle {...props} />;
};