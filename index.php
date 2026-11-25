<?php
declare(strict_types=1);

/**
 * WASLA — front controller (ADR-0002, SEC-08).
 * Real Phase 4 router: same route keys as the Phase 3 skeleton, now dispatching
 * to controllers. GET renders, POST mutates (CSRF-guarded inside handlers).
 */

use App\Controllers\Administration;
use App\Controllers\Citizen;
use App\Controllers\Mediateur;
use App\Controllers\Technical;
use App\Core\Lang;
use App\Core\Response;
use App\Core\Rbac;
use App\Core\Settings;
use App\Core\View;

require __DIR__ . '/app/bootstrap.php';

// ── installer gate (D9) ──
if (!\App\Core\InstallLock::isInstalled()) {
    Response::redirect('install.php');
}

// ── locale (INTL-01): explicit ?lang= wins, else platform default (D8) ──
$langParam = $_GET['lang'] ?? null;
Lang::setLocale(is_string($langParam) ? $langParam : Settings::get('app.default_language', 'ar'));

// ── maintenance mode (T-03): technical admins stay inside (W-08: login and
// logout stay reachable, otherwise a timed-out session locks everyone out) ──
$routeKey = (string) ($_GET['r'] ?? 'home');
if (Settings::get('app.maintenance_mode', '0') === '1'
    && !in_array($routeKey, ['login', 'logout'], true)
    && !(Rbac::role() === 'technical_admin')) {
    http_response_code(503);
    View::render('citizen', 'error', [
        'routeKey' => 'error/503', 'space' => 'citizen',
        'pageTitle' => t('app.maintenance'),
        'errorCode' => '503',
    ]);
    exit;
}

/** route key => [rbac space, GET handler, POST handler] */
const ROUTES = [
    // citizen (public + account)
    'home'               => ['citizen', [Citizen\PageController::class, 'home'], null],
    'about'              => ['citizen', [Citizen\PageController::class, 'about'], null],
    'complaint/submit'   => ['citizen', [Citizen\ComplaintController::class, 'showForm'], [Citizen\ComplaintController::class, 'submit']],
    'complaint/success'  => ['citizen', [Citizen\ComplaintController::class, 'success'], null],
    'complaint/reply'    => ['citizen', null, [Citizen\ComplaintController::class, 'reply']],
    'register-report'    => ['citizen', [Citizen\RegisterReportController::class, 'showForm'], [Citizen\RegisterReportController::class, 'submit']],
    'reception'          => ['citizen', [Citizen\ReceptionController::class, 'showForm'], [Citizen\ReceptionController::class, 'submit']],
    'disclosure'         => ['citizen', [Citizen\DisclosureController::class, 'showForm'], [Citizen\DisclosureController::class, 'submit']],
    'track'              => ['citizen', [Citizen\TrackingController::class, 'showForm'], null],
    'track/result'       => ['citizen', [Citizen\TrackingController::class, 'resultGet'], [Citizen\TrackingController::class, 'result']],
    'login'              => ['citizen', [Citizen\AuthController::class, 'loginForm'], [Citizen\AuthController::class, 'login']],
    'register'           => ['citizen', [Citizen\AuthController::class, 'registerForm'], [Citizen\AuthController::class, 'register']],
    'logout'             => ['citizen', [Citizen\AuthController::class, 'logoutGet'], [Citizen\AuthController::class, 'logout']],
    'dashboard'          => ['citizen', [Citizen\AccountController::class, 'dashboard'], null],
    'complaints/detail'  => ['citizen', [Citizen\ComplaintController::class, 'detail'], null],
    'profile'            => ['citizen', [Citizen\AccountController::class, 'profile'], [Citizen\AccountController::class, 'saveProfile']],
    'notifications'      => ['citizen', [Citizen\AccountController::class, 'notifications'], [Citizen\AccountController::class, 'markNotificationsRead']],
    'attachment'         => ['citizen', [Citizen\AttachmentController::class, 'download'], null],
    // administration
    'admin'              => ['administration', [Administration\DashboardController::class, 'index'], null],
    'admin/complaints'   => ['administration', [Administration\ComplaintController::class, 'list'], null],
    'admin/complaint'    => ['administration', [Administration\ComplaintController::class, 'detail'], [Administration\ComplaintController::class, 'action']],
    'admin/reports'      => ['administration', [Administration\ReportController::class, 'list'], [Administration\ReportController::class, 'action']],
    'admin/receptions'   => ['administration', [Administration\ReceptionController::class, 'list'], null],
    'admin/disclosure'   => ['administration', [Administration\DisclosureController::class, 'queue'], [Administration\DisclosureController::class, 'review']],
    // mediateur (holds administration + mediateur spaces, D4)
    'med'                => ['mediateur', [Mediateur\DashboardController::class, 'index'], null],
    'med/review'         => ['mediateur', [Mediateur\ReviewController::class, 'detail'], [Mediateur\ReviewController::class, 'action']],
    'med/verifications'  => ['mediateur', [Mediateur\VerificationController::class, 'list'], [Mediateur\VerificationController::class, 'outcome']],
    'med/appointments'   => ['mediateur', [Mediateur\AppointmentController::class, 'list'], [Mediateur\AppointmentController::class, 'action']],
    'med/statistics'     => ['mediateur', [Mediateur\StatisticsController::class, 'index'], null],
    'med/archive'        => ['mediateur', [Mediateur\ArchiveController::class, 'index'], null],
    // technical admin
    'tech'               => ['technical_admin', [Technical\DashboardController::class, 'index'], null],
    'tech/accounts'      => ['technical_admin', [Technical\AccountController::class, 'list'], [Technical\AccountController::class, 'action']],
    'tech/permissions'   => ['technical_admin', [Technical\PermissionController::class, 'index'], [Technical\PermissionController::class, 'save']],
    'tech/settings'      => ['technical_admin', [Technical\SettingController::class, 'index'], [Technical\SettingController::class, 'save']],
    'tech/audit-logs'    => ['technical_admin', [Technical\LogController::class, 'audit'], null],
    'tech/security-logs' => ['technical_admin', [Technical\LogController::class, 'security'], null],
    'tech/backup'        => ['technical_admin', [Technical\BackupController::class, 'index'], [Technical\BackupController::class, 'action']],
    'tech/errors'        => ['technical_admin', [Technical\LogController::class, 'errors'], null],
];

/** Account-holder routes inside the citizen space (auth required, GET too). */
const CITIZEN_GATED = ['dashboard', 'complaints/detail', 'profile', 'notifications'];
// NOTE (audit fix): 'logout' is NOT gated here — requireSpace('citizen') would
// 403 mediateur/technical accounts and make logout impossible for them. Both
// logout handlers guard guests themselves.

$routeKey = (string) ($_GET['r'] ?? 'home');
if (!isset(ROUTES[$routeKey])) {
    Citizen\PageController::error(404);
}
[$space, $getHandler, $postHandler] = ROUTES[$routeKey];

$isPost = ($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST';
$handler = $isPost ? $postHandler : $getHandler;
if ($handler === null) {
    if ($isPost) {
        Citizen\PageController::error(405);
    }
    Citizen\PageController::error(404);
}

// RBAC enforcement: institutional spaces + gated citizen routes (SEC-08)
if ($space !== 'citizen') {
    Rbac::requireSpace($space);
} elseif (in_array($routeKey, CITIZEN_GATED, true)) {
    Rbac::requireSpace('citizen');
}

call_user_func($handler);
