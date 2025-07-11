pub mod api;
pub mod components;
pub mod contexts;
pub mod hooks;
pub mod middleware;
pub mod pages;
pub mod repositories;
pub mod server;
pub mod services;
pub mod utils;

use components::layout::{AppLayout, ThemeProvider};
use components::ui::*;
use contexts::app_state::provide_app_state;
use contexts::auth::AuthProvider;
use leptos::prelude::*;
use leptos_router::{components::*, path};
use pages::{DashboardContent, GroupsPage, MembersPage, Settings, LoginPage, SignupPage};

#[component]
pub fn App() -> impl IntoView {
    provide_app_state();

    view! {
        <AuthProvider>
            <Router>
                <Routes fallback=|| view! { <NotFoundPage/> }.into_any()>
                    <Route path=path!("/") view=LayoutedLogin/>
                    <Route path=path!("/login") view=LayoutedLogin/>
                    <Route path=path!("/signup") view=LayoutedSignup/>
                    <Route path=path!("/dashboard") view=LayoutedDashboard/>
                    <Route path=path!("/settings") view=LayoutedSettings/>
                    <Route path=path!("/members") view=LayoutedMembers/>
                    <Route path=path!("/groups") view=LayoutedGroups/>
                    <Route path=path!("/shares") view=LayoutedShares/>
                    <Route path=path!("/health") view=HealthPage/>
                </Routes>
            </Router>
            <ToastContainer/>
        </AuthProvider>
    }
}

#[component]
fn LayoutedDashboard() -> impl IntoView {
    view! {
        <html>
            <head>
                <title>"Dashboard - BitsaccoServer"</title>
                <meta charset="utf-8"/>
                <meta name="viewport" content="width=device-width, initial-scale=1"/>
                <link rel="stylesheet" href="/assets/styles.css"/>
                <style>
                    r#"
                    * { box-sizing: border-box; margin: 0; padding: 0; }
                    body { font-family: 'Inter', system-ui, sans-serif; }
                    "#
                </style>
            </head>
            <body>
                <ThemeProvider>
                    <AppLayout>
                        <DashboardContent/>
                    </AppLayout>
                </ThemeProvider>
            </body>
        </html>
    }
}

#[component]
fn LayoutedSettings() -> impl IntoView {
    view! {
        <html>
            <head>
                <title>"Settings - BitsaccoServer"</title>
                <meta charset="utf-8"/>
                <meta name="viewport" content="width=device-width, initial-scale=1"/>
                <link rel="stylesheet" href="/assets/styles.css"/>
                <style>
                    r#"
                    * { box-sizing: border-box; margin: 0; padding: 0; }
                    body { font-family: 'Inter', system-ui, sans-serif; }
                    "#
                </style>
            </head>
            <body>
                <ThemeProvider>
                    <AppLayout>
                        <Settings/>
                    </AppLayout>
                </ThemeProvider>
            </body>
        </html>
    }
}

#[component]
fn LayoutedMembers() -> impl IntoView {
    view! {
        <html>
            <head>
                <title>"Members - BitsaccoServer"</title>
                <meta charset="utf-8"/>
                <meta name="viewport" content="width=device-width, initial-scale=1"/>
                <link rel="stylesheet" href="/assets/styles.css"/>
                <style>
                    r#"
                    * { box-sizing: border-box; margin: 0; padding: 0; }
                    body { font-family: 'Inter', system-ui, sans-serif; }
                    "#
                </style>
            </head>
            <body>
                <ThemeProvider>
                    <AppLayout>
                        <MembersPage/>
                    </AppLayout>
                </ThemeProvider>
            </body>
        </html>
    }
}

#[component]
fn LayoutedGroups() -> impl IntoView {
    view! {
        <html>
            <head>
                <title>"Groups - BitsaccoServer"</title>
                <meta charset="utf-8"/>
                <meta name="viewport" content="width=device-width, initial-scale=1"/>
                <link rel="stylesheet" href="/assets/styles.css"/>
                <style>
                    r#"
                    * { box-sizing: border-box; margin: 0; padding: 0; }
                    body { font-family: 'Inter', system-ui, sans-serif; }
                    "#
                </style>
            </head>
            <body>
                <ThemeProvider>
                    <AppLayout>
                        <GroupsPage/>
                    </AppLayout>
                </ThemeProvider>
            </body>
        </html>
    }
}

#[component]
fn LayoutedShares() -> impl IntoView {
    view! {
        <html>
            <head>
                <title>"Shares - BitsaccoServer"</title>
                <meta charset="utf-8"/>
                <meta name="viewport" content="width=device-width, initial-scale=1"/>
                <link rel="stylesheet" href="/assets/styles.css"/>
                <style>
                    r#"
                    * { box-sizing: border-box; margin: 0; padding: 0; }
                    body { font-family: 'Inter', system-ui, sans-serif; }
                    "#
                </style>
            </head>
            <body>
                <ThemeProvider>
                    <AppLayout>
                        <pages::shares::SharesPage/>
                    </AppLayout>
                </ThemeProvider>
            </body>
        </html>
    }
}

#[component]
fn LayoutedLogin() -> impl IntoView {
    view! {
        <html>
            <head>
                <title>"Sign In - BitsaccoServer"</title>
                <meta charset="utf-8"/>
                <meta name="viewport" content="width=device-width, initial-scale=1"/>
                <link rel="stylesheet" href="/assets/styles.css"/>
                <style>
                    r#"
                    * { box-sizing: border-box; margin: 0; padding: 0; }
                    body { font-family: 'Inter', system-ui, sans-serif; }
                    "#
                </style>
            </head>
            <body>
                <ThemeProvider>
                    <LoginPage />
                </ThemeProvider>
            </body>
        </html>
    }
}

#[component]
fn LayoutedSignup() -> impl IntoView {
    view! {
        <html>
            <head>
                <title>"Sign Up - BitsaccoServer"</title>
                <meta charset="utf-8"/>
                <meta name="viewport" content="width=device-width, initial-scale=1"/>
                <link rel="stylesheet" href="/assets/styles.css"/>
                <style>
                    r#"
                    * { box-sizing: border-box; margin: 0; padding: 0; }
                    body { font-family: 'Inter', system-ui, sans-serif; }
                    "#
                </style>
            </head>
            <body>
                <ThemeProvider>
                    <SignupPage />
                </ThemeProvider>
            </body>
        </html>
    }
}

#[component]
fn DashboardPage() -> impl IntoView {
    view! {
        <div class="min-h-screen bg-gray-50">
            <div class="bg-white shadow">
                <div class="px-4 sm:px-6 lg:max-w-6xl lg:mx-auto lg:px-8">
                    <div class="py-6 md:flex md:items-center md:justify-between">
                        <div class="flex-1 min-w-0">
                            <h1 class="text-2xl font-bold leading-7 text-gray-900 sm:text-3xl sm:truncate">
                                "Dashboard"
                            </h1>
                        </div>
                    </div>
                </div>
            </div>
            <div class="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
                <div class="grid grid-cols-1 gap-5 sm:grid-cols-3">
                    <div class="bg-white overflow-hidden shadow rounded-lg">
                        <div class="p-5">
                            <div class="flex items-center">
                                <div class="flex-shrink-0">
                                    <div class="text-sm font-medium text-gray-500">"Total Members"</div>
                                </div>
                            </div>
                            <div class="mt-1 flex items-baseline">
                                <div class="text-2xl font-semibold text-gray-900">"1,247"</div>
                            </div>
                        </div>
                    </div>
                    <div class="bg-white overflow-hidden shadow rounded-lg">
                        <div class="p-5">
                            <div class="flex items-center">
                                <div class="flex-shrink-0">
                                    <div class="text-sm font-medium text-gray-500">"Total Value"</div>
                                </div>
                            </div>
                            <div class="mt-1 flex items-baseline">
                                <div class="text-2xl font-semibold text-gray-900">"$2.3M"</div>
                            </div>
                        </div>
                    </div>
                    <div class="bg-white overflow-hidden shadow rounded-lg">
                        <div class="p-5">
                            <div class="flex items-center">
                                <div class="flex-shrink-0">
                                    <div class="text-sm font-medium text-gray-500">"Active Offers"</div>
                                </div>
                            </div>
                            <div class="mt-1 flex items-baseline">
                                <div class="text-2xl font-semibold text-gray-900">"23"</div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    }
}

#[component]
fn NotFoundPage() -> impl IntoView {
    view! {
        <div class="min-h-screen bg-gray-50 flex items-center justify-center">
            <div class="text-center">
                <h1 class="text-6xl font-bold text-gray-400">"404"</h1>
                <h2 class="text-2xl font-semibold text-gray-900 mt-4">"Page not found"</h2>
                <p class="text-gray-600 mt-2">"The page you're looking for doesn't exist."</p>
                <div class="mt-6">
                    <a href="/dashboard" class="inline-flex items-center px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700">
                        "Go to Dashboard"
                    </a>
                </div>
            </div>
        </div>
    }
}

#[component]
fn HealthPage() -> impl IntoView {
    view! {
        <div class="bg-white shadow rounded-lg p-6">
            <h1 class="text-2xl font-bold text-green-600 mb-6">"System Health"</h1>
            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                <HealthCard
                    title="Server"
                    status="Online"
                    color="green"
                    details="Running smoothly"
                />
                <HealthCard
                    title="Database"
                    status="Connected"
                    color="green"
                    details="PostgreSQL 16"
                />
                <HealthCard
                    title="Cache"
                    status="Ready"
                    color="green"
                    details="Redis active"
                />
                <HealthCard
                    title="Authentication"
                    status="Active"
                    color="green"
                    details="Keycloak integration"
                />
                <HealthCard
                    title="API"
                    status="Operational"
                    color="green"
                    details="All endpoints responding"
                />
                <HealthCard
                    title="Storage"
                    status="Available"
                    color="green"
                    details="85% capacity"
                />
            </div>
        </div>
    }
}

#[component]
fn HealthCard(
    title: &'static str,
    status: &'static str,
    color: &'static str,
    details: &'static str,
) -> impl IntoView {
    let (bg_color, text_color, dot_color) = match color {
        "green" => ("bg-green-50", "text-green-800", "bg-green-500"),
        "yellow" => ("bg-yellow-50", "text-yellow-800", "bg-yellow-500"),
        "red" => ("bg-red-50", "text-red-800", "bg-red-500"),
        _ => ("bg-gray-50", "text-gray-800", "bg-gray-500"),
    };

    view! {
        <div class={format!("p-4 rounded-lg {}", bg_color)}>
            <div class="flex items-center">
                <div class={format!("w-3 h-3 rounded-full mr-3 {}", dot_color)}></div>
                <h3 class={format!("font-medium {}", text_color)}>{title}</h3>
            </div>
            <div class="mt-2">
                <p class={format!("text-sm font-semibold {}", text_color)}>{status}</p>
                <p class={format!("text-xs {}", text_color.replace("800", "600"))}>{details}</p>
            </div>
        </div>
    }
}
