package main

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

func (m model) View() string {
	if m.quitting {
		return ""
	}
	if m.state == stateList {
		header := renderHeader(len(m.rawHosts), countContainers(m.rawHosts))

		var scanStatus string
		if m.scanning {
			scanStatus = "\n " + m.spinner.View() + " " +
				lipgloss.NewStyle().Foreground(colorSecondary).Render("Scanning containers...") + "\n"
		}
		var deleteStatus string
		if m.listDeleteArmed {
			deleteStatus = "\n " + testFailStyle.Render("Press d again to delete "+m.listDeleteType+": "+m.listDeleteLabel+" (Esc to cancel)") + "\n"
		}

		var importStatus string
		if m.statusMessage != "" {
			style := testSuccessStyle
			marker := "✔"
			if m.statusIsError {
				style = testFailStyle
				marker = "✘"
			}
			importStatus = "\n " + style.Render(marker+" "+m.statusMessage) + "\n"
		}

		content := header + m.list.View() + scanStatus + deleteStatus + importStatus
		if m.err != nil {
			content += "\n" + testFailStyle.Render(" Config warning: "+m.err.Error())
		}
		help := "\n" + renderListHelp()
		return appStyle.Render(content + help)
	}
	if m.state == stateFilePicker {
		title := formTitleStyle.Render("📂 Select Identity File")
		content := fpBoxStyle.Render(m.filepicker.View())
		help := "\n" + renderFilePickerHelp()
		return appStyle.Render(title + "\n\n" + content + help)
	}
	if m.state == stateHistory {
		title := formTitleStyle.Render("Recent Connections")
		content := title + "\n\n" + m.historyList.View()
		help := "\n" + renderHistoryHelp()
		return appStyle.Render(content + help)
	}
	if m.state == stateGroupPrompt {
		title := "New Group"
		if m.groupAction == "rename" {
			title = "Rename Group"
		}
		box := formBoxStyle.Render(formTitleStyle.Render(title) + "\n\n" + m.groupInput.View())
		help := "\n" + helpBarStyle.Render(helpEntry("enter", "save")+" | "+helpEntry("esc", "cancel"))
		return appStyle.Render(box + help)
	}
	// Form View
	var formTitle string
	if m.selectedHost == nil {
		formTitle = formTitleStyle.Render("✨ New Session")
	} else {
		formTitle = formTitleStyle.Render("✏️  Edit Session")
	}

	divider := formDividerStyle.Render(strings.Repeat("─", 40))

	// Build form content
	var formContent strings.Builder
	formContent.WriteString(formTitle + "\n\n")

	// Connection section
	formContent.WriteString(lipgloss.NewStyle().Foreground(colorSecondary).Bold(true).Render("  CONNECTION") + "\n")
	formContent.WriteString(divider + "\n")
	for i := 0; i < 4; i++ {
		formContent.WriteString(m.inputs[i].View() + "\n")
	}

	formContent.WriteString("\n")
	// Auth section
	formContent.WriteString(lipgloss.NewStyle().Foreground(colorSecondary).Bold(true).Render("  AUTHENTICATION") + "\n")
	formContent.WriteString(divider + "\n")
	pickStyle := lipgloss.NewStyle().
		Foreground(colorText).
		Background(colorSecondary).
		Bold(true).
		Padding(0, 1)
	if m.focusIndex == 4 && m.keyPickFocus {
		pickStyle = pickStyle.Background(colorPrimary)
	}
	formContent.WriteString(lipgloss.JoinHorizontal(lipgloss.Top, m.inputs[4].View(), "  ", pickStyle.Render("Pick")) + "\n")
	formContent.WriteString(m.inputs[5].View() + "\n")

	formContent.WriteString("\n")
	formContent.WriteString(lipgloss.NewStyle().Foreground(colorSecondary).Bold(true).Render("  GROUPS") + "\n")
	formContent.WriteString(divider + "\n")
	if m.groupCustom {
		formContent.WriteString(m.inputs[6].View() + "\n")
	} else {
		groupLabelStyle := lipgloss.NewStyle().Foreground(colorMuted)
		groupValueStyle := lipgloss.NewStyle().Foreground(colorDimText)
		if m.focusIndex == 6 {
			groupLabelStyle = lipgloss.NewStyle().Foreground(colorPrimary).Bold(true)
			groupValueStyle = lipgloss.NewStyle().Foreground(colorText)
		}
		groupValue := "(none)"
		if len(m.groupOptions) > 0 {
			groupValue = m.groupOptions[m.groupIndex]
		}
		formContent.WriteString(groupLabelStyle.Render("  Group       ") + groupValueStyle.Render("◀ "+groupValue+" ▶") + "\n")
	}

	if m.selectedHost != nil {
		label := "Delete Host"
		if m.deleteArmed {
			label = "Press Enter to Confirm Delete"
		}
		deleteStyle := lipgloss.NewStyle().
			Foreground(colorText).
			Background(colorDanger).
			Bold(true).
			Padding(0, 1)
		if !m.deleteFocus {
			deleteStyle = lipgloss.NewStyle().
				Foreground(colorDimText).
				Background(colorSubtle).
				Padding(0, 1)
		}
		formContent.WriteString("\n  " + deleteStyle.Render(label) + "\n")
		if m.deleteArmed {
			formContent.WriteString("  " + formHintStyle.Render("Esc to cancel") + "\n")
		}
	}

	// Test status
	if m.testing {
		formContent.WriteString("\n " + m.spinner.View() + " " +
			testPendingStyle.Render("Testing connection..."))
	} else if m.testStatus != "" {
		if m.testResult {
			formContent.WriteString("\n  " + testSuccessStyle.Render("✔ "+m.testStatus))
		} else {
			formContent.WriteString("\n  " + testFailStyle.Render("✘ "+m.testStatus))
		}
	}
	if m.formError != "" {
		formContent.WriteString("\n  " + testFailStyle.Render("✘ "+m.formError))
	}

	form := formBoxStyle.Render(formContent.String())
	help := "\n" + renderFormHelp()

	return appStyle.Render(form + help)
}
