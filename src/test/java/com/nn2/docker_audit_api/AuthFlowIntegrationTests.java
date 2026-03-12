package com.nn2.docker_audit_api;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
class AuthFlowIntegrationTests {

	@Autowired
	private MockMvc mockMvc;

	@Test
	void loginReturnsRoleAwarePayload() throws Exception {
		mockMvc.perform(post("/api/auth/login")
				.contentType(MediaType.APPLICATION_JSON)
				.content("""
					{
					  "username": "engineer",
					  "password": "engineer123"
					}
					"""))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.role").value("SECURITY_ENGINEER"))
			.andExpect(jsonPath("$.homePath").value("/security-engineer"));
	}

	@Test
	void developerCannotOpenSuperAdminWorkspace() throws Exception {
		MockHttpSession session = (MockHttpSession) mockMvc.perform(post("/api/auth/login")
				.contentType(MediaType.APPLICATION_JSON)
				.content("""
					{
					  "username": "developer",
					  "password": "developer123"
					}
					"""))
			.andExpect(status().isOk())
			.andReturn()
			.getRequest()
			.getSession(false);

		mockMvc.perform(get("/api/pages/super-admin").session(session))
			.andExpect(status().isForbidden())
			.andExpect(jsonPath("$.message").value("Access denied"));
	}
}