import { RadioGroup } from "@headlessui/react";

import { useUser } from "@supabase/auth-helpers-react";
import { useState } from "react";
import { getJawnClient } from "../../../lib/clients/jawn";
import { DEMO_EMAIL } from "../../../lib/constants";
import { useOrg } from "../../layout/organizationContext";
import { clsx } from "../../shared/clsx";
import useNotification from "../../shared/notification/useNotification";
import ProviderKeyList from "../enterprise/portal/id/providerKeyList";
import CreateProviderKeyModal from "../vault/createProviderKeyModal";
import { useVaultPage } from "../vault/useVaultPage";
import { ORGANIZATION_COLORS, ORGANIZATION_ICONS } from "./orgConstants";
import {
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { useTranslation } from "react-i18next";

interface CreateOrgFormProps {
  variant?: "organization" | "reseller";
  onCancelHandler?: (open: boolean) => void;
  initialValues?: {
    id: string;
    name: string;
    color: string | null;
    icon: string | null;
    providerKey: string | null;
    limits?: OrgLimits;
    referral?: string;
  };
  firstOrg?: boolean;
  onSuccess?: (param?: string) => void;
}

export type OrgLimits = {
  cost: number;
  requests: number;
} | null;

const CreateOrgForm = (props: CreateOrgFormProps) => {
  const {
    variant = "organization",
    onCancelHandler,
    initialValues,
    onSuccess,
    firstOrg,
  } = props;

  const [orgName, setOrgName] = useState(initialValues?.name || "");
  const [limits, setLimits] = useState<{
    cost: number;
    requests: number;
  } | null>(
    variant === "reseller"
      ? initialValues?.limits
        ? initialValues.limits
        : {
            cost: 1_000,
            requests: 1_000,
          }
      : null
  );
  const [selectedColor, setSelectedColor] = useState(
    initialValues?.color
      ? ORGANIZATION_COLORS.find((c) => c.name === initialValues.color) ||
          ORGANIZATION_COLORS[0]
      : ORGANIZATION_COLORS[0]
  );
  const [selectedIcon, setSelectedIcon] = useState(
    initialValues?.icon
      ? ORGANIZATION_ICONS.find((i) => i.name === initialValues.icon) ||
          ORGANIZATION_ICONS[0]
      : ORGANIZATION_ICONS[0]
  );

  const [referralType, setReferralType] = useState(
    initialValues?.referral || "friend_referral"
  );

  const user = useUser();
  const orgContext = useOrg();
  const { setNotification } = useNotification();
  const [providerKey, setProviderKey] = useState(
    initialValues?.providerKey || ""
  );

  const { refetchProviderKeys } = useVaultPage();

  const [isProviderOpen, setIsProviderOpen] = useState(false);

  const { t } = useTranslation();
  const referralOptions = [
    { value: "friend_referral", label: t("Friend (referral)") },
    { value: "google", label: t("Google") },
    { value: "twitter", label: t("Twitter") },
    { value: "linkedin", label: t("LinkedIn") },
    { value: "microsoft_startups", label: t("Microsoft for Startups") },
    { value: "product_hunt", label: t("Product Hunt") },
    { value: "other", label: t("Other") },
  ];

  return (
    <>
      <div>
        {initialValues || variant === "reseller" ? (
          <></>
        ) : (
          <>
            <DialogHeader className="space-y-2">
              <DialogTitle>
                {firstOrg ? "Getting Started" : "Create New Organization"}
              </DialogTitle>
              {firstOrg && (
                <DialogDescription>
                  Let’s help you create your first organization.
                </DialogDescription>
              )}
            </DialogHeader>
          </>
        )}
        <div className="flex flex-col w-full space-y-6 mt-8">
          <div className="space-y-1.5 text-sm">
            <Label htmlFor="org-name">
              {
                {
                  organization: "Organization Name",
                  reseller: "Customer Name",
                }[variant]
              }
            </Label>
            <Input
              type="text"
              name="org-name"
              id="org-name"
              value={orgName}
              placeholder={
                variant === "organization"
                  ? "Your shiny new org name"
                  : "Customer name"
              }
              onChange={(e) => setOrgName(e.target.value)}
            />
          </div>
          <RadioGroup value={selectedColor} onChange={setSelectedColor}>
            <RadioGroup.Label className="block text-sm font-medium leading-6 text-slate-900 dark:text-slate-100">
              Choose a color
            </RadioGroup.Label>
            <div className="mt-4 flex items-center justify-between px-8">
              {ORGANIZATION_COLORS.map((color) => (
                <RadioGroup.Option
                  key={color.name}
                  value={color}
                  className={({ active, checked }) =>
                    clsx(
                      color.selectedColor,
                      active && checked ? "ring ring-offset-1" : "",
                      !active && checked ? "ring-2" : "",
                      "relative -m-0.5 flex cursor-pointer items-center justify-center rounded-full p-0.5 focus:outline-none"
                    )
                  }
                >
                  <RadioGroup.Label as="span" className="sr-only">
                    {color.name}
                  </RadioGroup.Label>
                  <span
                    aria-hidden="true"
                    className={clsx(
                      color.bgColor,
                      "h-8 w-8 rounded-full border border-black dark:border-white border-opacity-10"
                    )}
                  />
                </RadioGroup.Option>
              ))}
            </div>
          </RadioGroup>
          <RadioGroup value={selectedIcon} onChange={setSelectedIcon}>
            <RadioGroup.Label className="block text-sm font-medium leading-6 text-slate-900 dark:text-slate-100">
              Choose an icon
            </RadioGroup.Label>
            <div className="mt-4 grid grid-cols-5 gap-4">
              {ORGANIZATION_ICONS.map((icon) => (
                <RadioGroup.Option
                  key={icon.name}
                  value={icon}
                  className={({ active, checked }) =>
                    clsx(
                      checked
                        ? "ring-2 ring-offset-1 ring-sky-300 dark:ring-sky-700"
                        : "ring-1 ring-slate-200 dark:ring-slate-800",
                      "bg-white dark:bg-black rounded-md p-2 flex items-center justify-center"
                    )
                  }
                >
                  <RadioGroup.Label as="span" className="sr-only">
                    {icon.name}
                  </RadioGroup.Label>
                  {
                    <icon.icon
                      className={clsx(
                        "h-6 w-6 hover:cursor-pointer",
                        selectedColor.textColor
                      )}
                    />
                  }
                </RadioGroup.Option>
              ))}
            </div>
          </RadioGroup>
          {firstOrg && (
            <div className="space-y-1.5 text-sm">
              <Label htmlFor="org-referral">How did you hear about us?</Label>
              <Select value={referralType} onValueChange={setReferralType}>
                <SelectTrigger>
                  <SelectValue placeholder={t("Select referral source")} />
                </SelectTrigger>
                <SelectContent>
                  {referralOptions.map((option) => (
                    <SelectItem key={option.value} value={option.value}>
                      {option.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          )}
          {variant === "reseller" && (
            <>
              <div>
                <label
                  htmlFor="org-limits"
                  className="block text-sm font-medium leading-6 text-slate-900 dark:text-slate-100"
                >
                  Limits
                </label>
                <div className="flex flex-row mx-auto gap-4">
                  <div className="space-y-1 text-sm">
                    <label
                      htmlFor="org-costs"
                      className="block text-xs leading-6 text-slate-500 "
                    >
                      Costs (USD)
                    </label>
                    <div className="flex flex-col gap-2">
                      <input
                        type="number"
                        name="org-costs"
                        id="org-costs"
                        disabled={limits?.cost !== -1}
                        value={
                          limits?.cost === -1 ? 9999999 : limits?.cost ?? 0
                        }
                        className={clsx(
                          "max-w-[10em] bg-slate-50 dark:bg-slate-950",
                          " block w-full rounded-md border-0 py-1.5",
                          "shadow-sm ring-1 ring-inset ring-slate-300 placeholder:text-slate-400 focus:ring-2",
                          "focus:ring-inset focus:ring-slate-600 text-sm lg:text-md lg:leading-6",
                          limits?.cost === -1
                            ? "text-slate-400"
                            : "text-black dark:text-white"
                        )}
                        onChange={(e) =>
                          setLimits((prev) =>
                            prev ? { ...prev, cost: +e.target.value } : null
                          )
                        }
                      />
                      <div className="flex gap-2 items-center">
                        <div>Unlimited</div>
                        <input
                          type="checkbox"
                          name="org-costs"
                          id="org-costs"
                          value={limits?.cost !== -1 ? 1 : 0}
                          className=""
                          onChange={(e) => {
                            if (limits?.cost === -1) {
                              setLimits((prev) =>
                                prev ? { ...prev, cost: 1000 } : null
                              );
                            } else {
                              setLimits((prev) =>
                                prev ? { ...prev, cost: -1 } : null
                              );
                            }
                          }}
                        />
                      </div>
                    </div>
                  </div>
                  <div className="space-y-1 text-sm">
                    <label
                      htmlFor="org-costs"
                      className="block text-xs leading-6 text-slate-500 "
                    >
                      Request
                    </label>
                    <div className="flex flex-col gap-2">
                      <input
                        type="number"
                        name="org-request"
                        id="org-request"
                        disabled={limits?.requests !== -1}
                        value={
                          limits?.requests === -1
                            ? 9999999
                            : limits?.requests ?? 0
                        }
                        className={clsx(
                          "max-w-[10em] bg-slate-50 dark:bg-slate-950",
                          " block w-full rounded-md border-0 py-1.5",
                          "shadow-sm ring-1 ring-inset ring-slate-300 placeholder:text-slate-400 focus:ring-2",
                          "focus:ring-inset focus:ring-slate-600 text-sm lg:text-md lg:leading-6",
                          limits?.requests === -1
                            ? "text-slate-400"
                            : "text-black dark:text-white"
                        )}
                        onChange={(e) =>
                          setLimits((prev) =>
                            prev ? { ...prev, requests: +e.target.value } : null
                          )
                        }
                      />
                      <div className="flex gap-2 items-center">
                        <div>Unlimited</div>
                        <input
                          type="checkbox"
                          name="org-requests"
                          id="org-requests"
                          value={limits?.requests !== -1 ? 1 : 0}
                          className=""
                          onChange={(e) => {
                            if (limits?.requests === -1) {
                              setLimits((prev) =>
                                prev ? { ...prev, requests: 1000 } : null
                              );
                            } else {
                              setLimits((prev) =>
                                prev ? { ...prev, requests: -1 } : null
                              );
                            }
                          }}
                        />
                      </div>
                    </div>
                  </div>

                  <div className="space-y-1 text-xs">
                    <label
                      htmlFor="org-time"
                      className="block text-xs leading-6 text-slate-500"
                    >
                      Time Grain
                    </label>
                    <select
                      id="org-size"
                      name="org-size"
                      className="max-w-[10em] bg-slate-50 dark:bg-slate-950 text-black dark:text-white block w-full rounded-md border-0 py-1.5 shadow-sm ring-1 ring-inset ring-slate-300 placeholder:text-slate-400 focus:ring-2 focus:ring-inset focus:ring-slate-600 text-sm lg:text-md lg:leading-6"
                      required
                    >
                      <option value="word">monthly</option>
                    </select>
                  </div>
                </div>
              </div>
              <ProviderKeyList
                orgProviderKey={initialValues?.providerKey || undefined}
                setProviderKeyCallback={setProviderKey}
              />
            </>
          )}
          <DialogFooter>
            {!firstOrg && (
              <Button
                variant="outline"
                onClick={() => {
                  if (onCancelHandler) {
                    onCancelHandler(false);
                  } else {
                    // reset to the initial values
                    setOrgName(initialValues?.name || "");
                    setSelectedColor(
                      initialValues?.color
                        ? ORGANIZATION_COLORS.find(
                            (c) => c.name === initialValues.color
                          ) || ORGANIZATION_COLORS[0]
                        : ORGANIZATION_COLORS[0]
                    );
                    setSelectedIcon(
                      initialValues?.icon
                        ? ORGANIZATION_ICONS.find(
                            (i) => i.name === initialValues.icon
                          ) || ORGANIZATION_ICONS[0]
                        : ORGANIZATION_ICONS[0]
                    );
                  }
                }}
              >
                Cancel
              </Button>
            )}
            <Button
              onClick={async () => {
                if ((user?.email ?? "") === DEMO_EMAIL) {
                  setNotification(
                    "Cannot create organization in demo mode",
                    "error"
                  );
                  return;
                }
                if (!orgName || orgName === "") {
                  setNotification(
                    "Please provide an organization name",
                    "error"
                  );
                  return;
                }
                if (variant === "reseller" && providerKey === "") {
                  setNotification("Please select a provider key", "error");
                  return;
                }
                const jawn = getJawnClient(orgContext?.currentOrg?.id);
                if (initialValues) {
                  const { error: updateOrgError } = await jawn.POST(
                    "/v1/organization/{organizationId}/update",
                    {
                      params: {
                        path: {
                          organizationId: initialValues.id,
                        },
                      },
                      body: {
                        name: orgName,
                        color: selectedColor.name,
                        icon: selectedIcon.name,
                        variant,
                        ...(variant === "reseller" && {
                          org_provider_key: providerKey,
                          limits: limits || undefined,
                          reseller_id: orgContext?.currentOrg?.id!,
                          organization_type: "customer",
                        }),
                      },
                    }
                  );

                  if (updateOrgError) {
                    setNotification("Failed to update organization", "error");
                  } else {
                    setNotification(
                      "Organization updated successfully",
                      "success"
                    );
                    onSuccess && onSuccess();
                  }
                  onCancelHandler && onCancelHandler(false);
                  orgContext?.refetchOrgs();
                } else {
                  const { error: createOrgError, data } = await jawn.POST(
                    "/v1/organization/create",
                    {
                      body: {
                        name: orgName,
                        owner: user?.id!,
                        color: selectedColor.name,
                        icon: selectedIcon.name,
                        has_onboarded: !firstOrg,
                        tier: "free",
                        ...(variant === "reseller" && {
                          org_provider_key: providerKey,
                          limits: limits || undefined,
                          reseller_id: orgContext?.currentOrg?.id!,
                          organization_type: "customer",
                        }),
                        ...(firstOrg && {
                          referral: referralType,
                        }),
                      },
                    }
                  );
                  if (createOrgError) {
                    setNotification(
                      "Failed to create organization" + createOrgError,
                      "error"
                    );
                  } else {
                    setNotification(
                      "Organization created successfully",
                      "success"
                    );
                    console.log("LMAOOOO", data?.data);
                    onSuccess && onSuccess(data?.data ?? "");
                  }
                  onCancelHandler && onCancelHandler(false);
                  orgContext?.refetchOrgs();
                }
              }}
            >
              {initialValues ? "Update" : "Create"}
            </Button>
          </DialogFooter>
        </div>
      </div>

      <CreateProviderKeyModal
        open={isProviderOpen}
        variant={"portal"}
        setOpen={setIsProviderOpen}
        onSuccess={() => refetchProviderKeys()}
      />
    </>
  );
};

export default CreateOrgForm;
