// Code generated by go generate; DO NOT EDIT.
package mailchimp

import "errors"

type Permission int

const (
    Invalid Permission = iota
    InviteUsers Permission = iota
    RevokeAccountAccess Permission = iota
    SetUserAccessLevel Permission = iota
    Require2FactorAuthentication Permission = iota
    ChangeBillingInformation Permission = iota
    ChangeCompanyOrganizationName Permission = iota
    AddOrAccessApiKeys Permission = iota
    CheckReconnectIntegrations Permission = iota
    ReferralProgram Permission = iota
    AccountExport Permission = iota
    CloseAccount Permission = iota
    AddFilesToContentStudio Permission = iota
    OptInToReceiveEmailsFromMailchimp Permission = iota
    CreateAudiences Permission = iota
    ViewAudiences Permission = iota
    AudienceExport Permission = iota
    AudienceImport Permission = iota
    AddContacts Permission = iota
    DeleteContacts Permission = iota
    ViewSegments Permission = iota
    EditAudienceSettings Permission = iota
    ArchiveContacts Permission = iota
    CreateOrImportTemplates Permission = iota
    EditTemplates Permission = iota
    CreateEmails Permission = iota
    EditEmails Permission = iota
    SendPublishEmails Permission = iota
    PauseUnpublishEmails Permission = iota
    DeleteEmails Permission = iota
    SubmitSmsMarketingApplication Permission = iota
    CreateSendSmsMmsMessages Permission = iota
    PurchaseSmsCredits Permission = iota
    ViewEmailReports Permission = iota
    ViewSmsReports Permission = iota
    ViewAbuseReports Permission = iota
    ViewEmailStatistics Permission = iota
    UseConversations Permission = iota
    ViewEmailRecipients Permission = iota
    TopLocations Permission = iota
    EmailContactDetails Permission = iota
    EmailOpenDetails Permission = iota
    ECommerceProductActivity Permission = iota
    DomainPerformance Permission = iota
    CreateYourWebsite Permission = iota
    PublishUnpublishYourWebsite Permission = iota
    ViewReport Permission = iota
    CreateALandingPage Permission = iota
    PublishUnpublishALandingPage Permission = iota
    ReplicateALandingPage Permission = iota
    VerifyADomain Permission = iota
    ConnectADomain Permission = iota
    CreateCustomerJourney Permission = iota
    ViewCustomerJourney Permission = iota
    EditCustomerJourney Permission = iota
    TurnOnPauseTurnBackOn Permission = iota
    ViewMessages Permission = iota
    LeaveComments Permission = iota
    SendMessages Permission = iota
    ToggleUserNotifications Permission = iota
    CreateSurvey Permission = iota
    EditSurvey Permission = iota
    PublishSurvey Permission = iota
    DeleteSurvey Permission = iota
    CreateForm Permission = iota
    EditForm Permission = iota
    PublishForm Permission = iota
    DeleteForm Permission = iota
)

var (
    PermissionStrings = map[Permission]string{
        InviteUsers: "invite_users",
        RevokeAccountAccess: "revoke_account_access",
        SetUserAccessLevel: "set_user_access_level",
        Require2FactorAuthentication: "require_2_factor_authentication",
        ChangeBillingInformation: "change_billing_information",
        ChangeCompanyOrganizationName: "change_company_organization_name",
        AddOrAccessApiKeys: "add_or_access_api_keys",
        CheckReconnectIntegrations: "check_reconnect_integrations",
        ReferralProgram: "referral_program",
        AccountExport: "account_export",
        CloseAccount: "close_account",
        AddFilesToContentStudio: "add_files_to_content_studio",
        OptInToReceiveEmailsFromMailchimp: "opt_in_to_receive_emails_from_mailchimp",
        CreateAudiences: "create_audiences",
        ViewAudiences: "view_audiences",
        AudienceExport: "audience_export",
        AudienceImport: "audience_import",
        AddContacts: "add_contacts",
        DeleteContacts: "delete_contacts",
        ViewSegments: "view_segments",
        EditAudienceSettings: "edit_audience_settings",
        ArchiveContacts: "archive_contacts",
        CreateOrImportTemplates: "create_or_import_templates",
        EditTemplates: "edit_templates",
        CreateEmails: "create_emails",
        EditEmails: "edit_emails",
        SendPublishEmails: "send_publish_emails",
        PauseUnpublishEmails: "pause_unpublish_emails",
        DeleteEmails: "delete_emails",
        SubmitSmsMarketingApplication: "submit_sms_marketing_application",
        CreateSendSmsMmsMessages: "create_send_sms_mms_messages",
        PurchaseSmsCredits: "purchase_sms_credits",
        ViewEmailReports: "view_email_reports",
        ViewSmsReports: "view_sms_reports",
        ViewAbuseReports: "view_abuse_reports",
        ViewEmailStatistics: "view_email_statistics",
        UseConversations: "use_conversations",
        ViewEmailRecipients: "view_email_recipients",
        TopLocations: "top_locations",
        EmailContactDetails: "email_contact_details",
        EmailOpenDetails: "email_open_details",
        ECommerceProductActivity: "e_commerce_product_activity",
        DomainPerformance: "domain_performance",
        CreateYourWebsite: "create_your_website",
        PublishUnpublishYourWebsite: "publish_unpublish_your_website",
        ViewReport: "view_report",
        CreateALandingPage: "create_a_landing_page",
        PublishUnpublishALandingPage: "publish_unpublish_a_landing_page",
        ReplicateALandingPage: "replicate_a_landing_page",
        VerifyADomain: "verify_a_domain",
        ConnectADomain: "connect_a_domain",
        CreateCustomerJourney: "create_customer_journey",
        ViewCustomerJourney: "view_customer_journey",
        EditCustomerJourney: "edit_customer_journey",
        TurnOnPauseTurnBackOn: "turn_on_pause_turn_back_on",
        ViewMessages: "view_messages",
        LeaveComments: "leave_comments",
        SendMessages: "send_messages",
        ToggleUserNotifications: "toggle_user_notifications",
        CreateSurvey: "create_survey",
        EditSurvey: "edit_survey",
        PublishSurvey: "publish_survey",
        DeleteSurvey: "delete_survey",
        CreateForm: "create_form",
        EditForm: "edit_form",
        PublishForm: "publish_form",
        DeleteForm: "delete_form",
    }

    StringToPermission = map[string]Permission{
        "invite_users": InviteUsers,
        "revoke_account_access": RevokeAccountAccess,
        "set_user_access_level": SetUserAccessLevel,
        "require_2_factor_authentication": Require2FactorAuthentication,
        "change_billing_information": ChangeBillingInformation,
        "change_company_organization_name": ChangeCompanyOrganizationName,
        "add_or_access_api_keys": AddOrAccessApiKeys,
        "check_reconnect_integrations": CheckReconnectIntegrations,
        "referral_program": ReferralProgram,
        "account_export": AccountExport,
        "close_account": CloseAccount,
        "add_files_to_content_studio": AddFilesToContentStudio,
        "opt_in_to_receive_emails_from_mailchimp": OptInToReceiveEmailsFromMailchimp,
        "create_audiences": CreateAudiences,
        "view_audiences": ViewAudiences,
        "audience_export": AudienceExport,
        "audience_import": AudienceImport,
        "add_contacts": AddContacts,
        "delete_contacts": DeleteContacts,
        "view_segments": ViewSegments,
        "edit_audience_settings": EditAudienceSettings,
        "archive_contacts": ArchiveContacts,
        "create_or_import_templates": CreateOrImportTemplates,
        "edit_templates": EditTemplates,
        "create_emails": CreateEmails,
        "edit_emails": EditEmails,
        "send_publish_emails": SendPublishEmails,
        "pause_unpublish_emails": PauseUnpublishEmails,
        "delete_emails": DeleteEmails,
        "submit_sms_marketing_application": SubmitSmsMarketingApplication,
        "create_send_sms_mms_messages": CreateSendSmsMmsMessages,
        "purchase_sms_credits": PurchaseSmsCredits,
        "view_email_reports": ViewEmailReports,
        "view_sms_reports": ViewSmsReports,
        "view_abuse_reports": ViewAbuseReports,
        "view_email_statistics": ViewEmailStatistics,
        "use_conversations": UseConversations,
        "view_email_recipients": ViewEmailRecipients,
        "top_locations": TopLocations,
        "email_contact_details": EmailContactDetails,
        "email_open_details": EmailOpenDetails,
        "e_commerce_product_activity": ECommerceProductActivity,
        "domain_performance": DomainPerformance,
        "create_your_website": CreateYourWebsite,
        "publish_unpublish_your_website": PublishUnpublishYourWebsite,
        "view_report": ViewReport,
        "create_a_landing_page": CreateALandingPage,
        "publish_unpublish_a_landing_page": PublishUnpublishALandingPage,
        "replicate_a_landing_page": ReplicateALandingPage,
        "verify_a_domain": VerifyADomain,
        "connect_a_domain": ConnectADomain,
        "create_customer_journey": CreateCustomerJourney,
        "view_customer_journey": ViewCustomerJourney,
        "edit_customer_journey": EditCustomerJourney,
        "turn_on_pause_turn_back_on": TurnOnPauseTurnBackOn,
        "view_messages": ViewMessages,
        "leave_comments": LeaveComments,
        "send_messages": SendMessages,
        "toggle_user_notifications": ToggleUserNotifications,
        "create_survey": CreateSurvey,
        "edit_survey": EditSurvey,
        "publish_survey": PublishSurvey,
        "delete_survey": DeleteSurvey,
        "create_form": CreateForm,
        "edit_form": EditForm,
        "publish_form": PublishForm,
        "delete_form": DeleteForm,
    }

    PermissionIDs = map[Permission]int{
        InviteUsers: 1,
        RevokeAccountAccess: 2,
        SetUserAccessLevel: 3,
        Require2FactorAuthentication: 4,
        ChangeBillingInformation: 5,
        ChangeCompanyOrganizationName: 6,
        AddOrAccessApiKeys: 7,
        CheckReconnectIntegrations: 8,
        ReferralProgram: 9,
        AccountExport: 10,
        CloseAccount: 11,
        AddFilesToContentStudio: 12,
        OptInToReceiveEmailsFromMailchimp: 13,
        CreateAudiences: 14,
        ViewAudiences: 15,
        AudienceExport: 16,
        AudienceImport: 17,
        AddContacts: 18,
        DeleteContacts: 19,
        ViewSegments: 20,
        EditAudienceSettings: 21,
        ArchiveContacts: 22,
        CreateOrImportTemplates: 23,
        EditTemplates: 24,
        CreateEmails: 25,
        EditEmails: 26,
        SendPublishEmails: 27,
        PauseUnpublishEmails: 28,
        DeleteEmails: 29,
        SubmitSmsMarketingApplication: 30,
        CreateSendSmsMmsMessages: 31,
        PurchaseSmsCredits: 32,
        ViewEmailReports: 33,
        ViewSmsReports: 34,
        ViewAbuseReports: 35,
        ViewEmailStatistics: 36,
        UseConversations: 37,
        ViewEmailRecipients: 38,
        TopLocations: 39,
        EmailContactDetails: 40,
        EmailOpenDetails: 41,
        ECommerceProductActivity: 42,
        DomainPerformance: 43,
        CreateYourWebsite: 44,
        PublishUnpublishYourWebsite: 45,
        ViewReport: 46,
        CreateALandingPage: 47,
        PublishUnpublishALandingPage: 48,
        ReplicateALandingPage: 49,
        VerifyADomain: 50,
        ConnectADomain: 51,
        CreateCustomerJourney: 52,
        ViewCustomerJourney: 53,
        EditCustomerJourney: 54,
        TurnOnPauseTurnBackOn: 55,
        ViewMessages: 56,
        LeaveComments: 57,
        SendMessages: 58,
        ToggleUserNotifications: 59,
        CreateSurvey: 60,
        EditSurvey: 61,
        PublishSurvey: 62,
        DeleteSurvey: 63,
        CreateForm: 64,
        EditForm: 65,
        PublishForm: 66,
        DeleteForm: 67,
    }

    IdToPermission = map[int]Permission{
        1: InviteUsers,
        2: RevokeAccountAccess,
        3: SetUserAccessLevel,
        4: Require2FactorAuthentication,
        5: ChangeBillingInformation,
        6: ChangeCompanyOrganizationName,
        7: AddOrAccessApiKeys,
        8: CheckReconnectIntegrations,
        9: ReferralProgram,
        10: AccountExport,
        11: CloseAccount,
        12: AddFilesToContentStudio,
        13: OptInToReceiveEmailsFromMailchimp,
        14: CreateAudiences,
        15: ViewAudiences,
        16: AudienceExport,
        17: AudienceImport,
        18: AddContacts,
        19: DeleteContacts,
        20: ViewSegments,
        21: EditAudienceSettings,
        22: ArchiveContacts,
        23: CreateOrImportTemplates,
        24: EditTemplates,
        25: CreateEmails,
        26: EditEmails,
        27: SendPublishEmails,
        28: PauseUnpublishEmails,
        29: DeleteEmails,
        30: SubmitSmsMarketingApplication,
        31: CreateSendSmsMmsMessages,
        32: PurchaseSmsCredits,
        33: ViewEmailReports,
        34: ViewSmsReports,
        35: ViewAbuseReports,
        36: ViewEmailStatistics,
        37: UseConversations,
        38: ViewEmailRecipients,
        39: TopLocations,
        40: EmailContactDetails,
        41: EmailOpenDetails,
        42: ECommerceProductActivity,
        43: DomainPerformance,
        44: CreateYourWebsite,
        45: PublishUnpublishYourWebsite,
        46: ViewReport,
        47: CreateALandingPage,
        48: PublishUnpublishALandingPage,
        49: ReplicateALandingPage,
        50: VerifyADomain,
        51: ConnectADomain,
        52: CreateCustomerJourney,
        53: ViewCustomerJourney,
        54: EditCustomerJourney,
        55: TurnOnPauseTurnBackOn,
        56: ViewMessages,
        57: LeaveComments,
        58: SendMessages,
        59: ToggleUserNotifications,
        60: CreateSurvey,
        61: EditSurvey,
        62: PublishSurvey,
        63: DeleteSurvey,
        64: CreateForm,
        65: EditForm,
        66: PublishForm,
        67: DeleteForm,
    }
)

// ToString converts a Permission enum to its string representation
func (p Permission) ToString() (string, error) {
    if str, ok := PermissionStrings[p]; ok {
        return str, nil
    }
    return "", errors.New("invalid permission")
}

// ToID converts a Permission enum to its ID
func (p Permission) ToID() (int, error) {
    if id, ok := PermissionIDs[p]; ok {
        return id, nil
    }
    return 0, errors.New("invalid permission")
}

// PermissionFromString converts a string representation to its Permission enum
func PermissionFromString(s string) (Permission, error) {
    if p, ok := StringToPermission[s]; ok {
        return p, nil
    }
    return 0, errors.New("invalid permission string")
}

// PermissionFromID converts an ID to its Permission enum
func PermissionFromID(id int) (Permission, error) {
    if p, ok := IdToPermission[id]; ok {
        return p, nil
    }
    return 0, errors.New("invalid permission ID")
}